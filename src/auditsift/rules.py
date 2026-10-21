"""Offline rules. Each one looks at a single file and returns candidates.

A candidate is a line the scanner is willing to defend with the code itself.
Later phases may explain it or throw it out. They do not invent new lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from auditsift.models import Candidate, is_placeholder, redact_secret
from auditsift.syntax import (
    blank_strings,
    call_window,
    docstring_mask,
    match_outside_strings,
    strip_comment,
)
from auditsift.taint import tainted_before
from auditsift.walk import SourceFile

_SECRET_NAME = r"(?:api[_-]?key|secret[_-]?key|password|passwd|token|access[_-]?key|private[_-]?key)"
SECRET_ASSIGN = re.compile(
    rf"(?i)\b[\w.-]*?{_SECRET_NAME}\b[^\n]{{0,60}}?(?<![=!<>])=(?!=)\s*"
    rf"(['\"])(?P<value>[^'\"\n]{{8,}})\1"
)
AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GH_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")

SQL_WORD = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b", re.I)
PARAM_EXECUTE = re.compile(r"""execute\s*\(\s*(['"])(?:(?!\1).)*\1\s*,""")
FSTRING = re.compile(r"""\bf['\"]""")
FORMAT_CALL = re.compile(r"\.format\s*\(")
PLUS_JOIN = re.compile(r"""['\"][^'\"]*['\"]\s*\+|\+\s*['\"]""")
PERCENT_FORMAT = re.compile(r"""['\"][^'\"]*%[sd][^'\"]*['\"]\s*%""")

SHELL_MARK = re.compile(r"\b(?:os\.system|os\.popen|subprocess\.getoutput)\s*\(|\bshell\s*=\s*True\b")
EVAL_CALL = re.compile(r"(?<![\w.])(?:eval|exec)\s*\(")
PICKLE_CALL = re.compile(r"(?<![\w.])(?:pickle\.(?:loads|load|Unpickler)|_pickle\.loads|marshal\.loads)\s*\(")
YAML_LOAD = re.compile(r"(?<![\w.])yaml\.load\s*\(")
YAML_UNSAFE = re.compile(r"(?<![\w.])yaml\.unsafe_load\s*\(")
WEAK_HASH = re.compile(r"hashlib\.(?:md5|sha1)\s*\(")
WEAK_CIPHER = re.compile(r"\bMODE_ECB\b|\bDES\.new\s*\(")
TLS_OFF = re.compile(
    r"verify\s*=\s*False|ssl\._create_unverified_context|\bCERT_NONE\b|"
    r"check_hostname\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true",
    re.I,
)
CORS_ORIGIN = re.compile(r"""(?i)(?:origins['\"]?\s*[:=]\s*['\"]\*['\"]|['\"]origins['\"]\s*:\s*['\"]\*['\"])""")
CORS_HEADER = re.compile(r"Access-Control-Allow-Origin")
DEBUG_RUN = re.compile(r"(?<![\w.])debug\s*=\s*True\b")
DEBUG_FLAG = re.compile(r"^\s*DEBUG\s*=\s*True\b")
PATH_CALL = re.compile(r"(?<![\w.])(?:open|send_file|send_from_directory|os\.path\.join)\s*\(")
SSRF_CALL = re.compile(
    r"(?<![\w.])(?:(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request)|"
    r"urllib\.request\.urlopen)\s*\("
)
PASSWORD_WORD = re.compile(r"\b(password|passwd|pwd)\b", re.I)


@dataclass(frozen=True)
class RuleInfo:
    id: str
    title: str
    severity: str
    summary: str
    impact: str
    fix: str


CATALOG: dict[str, RuleInfo] = {
    "AS-SECRET": RuleInfo(
        id="AS-SECRET",
        title="Hardcoded credential",
        severity="high",
        summary="A secret, token, or private key is stored in source.",
        impact="Anyone who can read the repository can reuse the credential.",
        fix="Read the value from the environment or a secret store, and rotate the leaked one.",
    ),
    "AS-SQLI": RuleInfo(
        id="AS-SQLI",
        title="SQL built with string interpolation",
        severity="high",
        summary="A SQL statement is assembled with an f-string, format, or concatenation.",
        impact="An attacker who controls the interpolated value can change the query.",
        fix="Use a parameterized query and pass values as bound parameters.",
    ),
    "AS-SHELL": RuleInfo(
        id="AS-SHELL",
        title="Shell command from external input",
        severity="high",
        summary="shell=True or os.system is combined with a value that is not a constant.",
        impact="Metacharacters in the input can run extra commands.",
        fix="Call the program with an argument list and shell=False.",
    ),
    "AS-EVAL": RuleInfo(
        id="AS-EVAL",
        title="Dynamic code execution",
        severity="high",
        summary="eval or exec runs a string as code.",
        impact="If any part of the string is attacker-controlled, they can run code.",
        fix="Replace eval/exec with a parser for the specific grammar you actually accept.",
    ),
    "AS-DESER": RuleInfo(
        id="AS-DESER",
        title="Unsafe deserialization",
        severity="high",
        summary="pickle, marshal, or yaml.load can instantiate objects from data.",
        impact="A crafted payload can execute code while it is being loaded.",
        fix="Use yaml.safe_load, or a format such as JSON that does not construct objects.",
    ),
    "AS-CRYPTO": RuleInfo(
        id="AS-CRYPTO",
        title="Weak hash or cipher",
        severity="medium",
        summary="MD5, SHA1, ECB, or DES is used where a modern primitive is expected.",
        impact="The construction is cheaper to attack than the password or token it protects.",
        fix="Use a password hash (scrypt, bcrypt, or argon2) or SHA-256 for checksums.",
    ),
    "AS-TLS": RuleInfo(
        id="AS-TLS",
        title="TLS verification disabled",
        severity="high",
        summary="Certificate checks are turned off on an HTTPS client.",
        impact="A network attacker can impersonate the remote host.",
        fix="Leave verification on. Pin a certificate only if you have a concrete reason.",
    ),
    "AS-PATH": RuleInfo(
        id="AS-PATH",
        title="Path built from request data",
        severity="high",
        summary="A filesystem call includes a value that came from the request.",
        impact="../ segments can escape the directory the handler meant to serve.",
        fix="Resolve the path and reject it unless it stays inside a fixed root.",
    ),
    "AS-CORS": RuleInfo(
        id="AS-CORS",
        title="Permissive CORS",
        severity="medium",
        summary="The service reflects every origin.",
        impact="A browser on another site can call authenticated endpoints.",
        fix="List the origins you actually ship, and do not combine * with credentials.",
    ),
    "AS-SSRF": RuleInfo(
        id="AS-SSRF",
        title="Request target from external input",
        severity="high",
        summary="An outbound HTTP call uses a URL that came from the request.",
        impact="The server can be turned into a proxy for internal addresses.",
        fix="Allow only known hosts, or drop the user-supplied URL entirely.",
    ),
    "AS-DEBUG": RuleInfo(
        id="AS-DEBUG",
        title="Debug mode enabled",
        severity="low",
        summary="A debug flag is left on.",
        impact="Interactive debuggers and extra traces leak internals on a crash.",
        fix="Turn debug off outside local development.",
    ),
}


def run_rules(source: SourceFile) -> list[Candidate]:
    lines = source.text.splitlines()
    masked = docstring_mask(lines)
    tainted = tainted_before(lines) if source.language == "python" else [set() for _ in lines]
    found: list[Candidate] = []
    found.extend(_secrets(source.rel, lines))
    found.extend(_sqli(source, lines, masked))
    found.extend(_shell(source, lines, masked, tainted))
    found.extend(_eval(source, lines, masked))
    found.extend(_deser(source, lines, masked))
    found.extend(_crypto(source, lines, masked))
    found.extend(_tls(source, lines, masked))
    found.extend(_cors(source, lines, masked))
    found.extend(_debug(source, lines, masked))
    if source.language == "python":
        found.extend(_paths(source, lines, masked, tainted))
        found.extend(_ssrf(source, lines, masked, tainted))
    return _dedupe(found)


def redact_snippet(rule_id: str, snippet: str) -> str:
    """Hide credential literals before they reach a report or a model."""
    if rule_id != "AS-SECRET":
        return snippet

    def repl(match: re.Match[str]) -> str:
        value = match.group("value")
        return match.group(0).replace(value, redact_secret(value), 1)

    text = SECRET_ASSIGN.sub(repl, snippet)
    for pattern in (AWS_KEY, GH_TOKEN, SLACK_TOKEN):
        text = pattern.sub(lambda match: redact_secret(match.group(0)), text)
    return text


def _dedupe(found: list[Candidate]) -> list[Candidate]:
    seen: set[tuple[str, str, int]] = set()
    unique: list[Candidate] = []
    for item in found:
        key = (item.rule_id, item.path, item.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def make(
    rule_id: str,
    path: str,
    line: int,
    message: str,
    snippet: str,
    *,
    end_line: int | None = None,
    severity: str | None = None,
) -> Candidate:
    info = CATALOG[rule_id]
    return Candidate(
        rule_id=rule_id,
        title=info.title,
        severity=severity or info.severity,
        path=path,
        line=line,
        end_line=end_line or line,
        message=message,
        snippet=snippet.strip("\n"),
    )


def _skip_secret_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name.endswith((".example", ".sample", ".template")) or name.endswith(".env.example")


def _secrets(path: str, lines: list[str]) -> list[Candidate]:
    if _skip_secret_file(path):
        return []
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        kind = _secret_kind(line)
        if not kind:
            continue
        found.append(
            make(
                "AS-SECRET",
                path,
                index + 1,
                f"Hardcoded credential ({kind}).",
                line.rstrip(),
            )
        )
    return found


def _secret_kind(line: str) -> str | None:
    if PRIVATE_KEY.search(line):
        return "private key"
    aws = AWS_KEY.search(line)
    if aws and not is_placeholder(aws.group(0)):
        return "cloud access key"
    token = GH_TOKEN.search(line) or SLACK_TOKEN.search(line)
    if token and not is_placeholder(token.group(0)):
        return "access token"
    assigned = SECRET_ASSIGN.search(line)
    if assigned and not is_placeholder(assigned.group("value")):
        return "assigned credential"
    return None


def _sqli(source: SourceFile, lines: list[str], masked: list[bool]) -> list[Candidate]:
    if source.language not in {None, "python", "javascript", "typescript", "php", "ruby", "java", "go"}:
        return []
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line, _comment_marker(source.language))
        if not _is_sqli(code):
            continue
        found.append(
            make(
                "AS-SQLI",
                source.rel,
                index + 1,
                "SQL query is built with string interpolation.",
                line.rstrip(),
            )
        )
    return found


def _is_sqli(code: str) -> bool:
    if not SQL_WORD.search(code):
        return False
    if PARAM_EXECUTE.search(code):
        return False
    if FSTRING.search(code) or FORMAT_CALL.search(code):
        return True
    if PLUS_JOIN.search(code) or PERCENT_FORMAT.search(code):
        return True
    return False


def _shell(
    source: SourceFile,
    lines: list[str],
    masked: list[bool],
    tainted: list[set[str]],
) -> list[Candidate]:
    if source.language not in {None, "python"}:
        return []
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line)
        if match_outside_strings(code, SHELL_MARK) is None:
            continue
        start, window = call_window(lines, index)
        if not _dynamic_command(window, tainted[index]):
            continue
        snippet = "\n".join(lines[j].rstrip() for j in range(start, index + 1))
        found.append(
            make(
                "AS-SHELL",
                source.rel,
                start + 1,
                "Shell command is built from external input.",
                snippet,
                end_line=index + 1,
            )
        )
    return found


def _dynamic_command(text: str, tainted: set[str]) -> bool:
    if FSTRING.search(text) or FORMAT_CALL.search(text) or PLUS_JOIN.search(text):
        return True
    if re.search(r"\brequest\s*\.", text):
        return True
    blank = blank_strings(text)
    return any(re.search(rf"\b{re.escape(name)}\b", blank) for name in tainted)


def _eval(source: SourceFile, lines: list[str], masked: list[bool]) -> list[Candidate]:
    if source.language not in {None, "python", "javascript", "typescript", "php", "ruby"}:
        return []
    marker = _comment_marker(source.language)
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line, marker)
        if match_outside_strings(code, EVAL_CALL) is None:
            continue
        found.append(
            make(
                "AS-EVAL",
                source.rel,
                index + 1,
                "eval or exec runs dynamic code.",
                line.rstrip(),
            )
        )
    return found


def _deser(source: SourceFile, lines: list[str], masked: list[bool]) -> list[Candidate]:
    if source.language not in {None, "python"}:
        return []
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line)
        kind = None
        if match_outside_strings(code, PICKLE_CALL):
            kind = "an unsafe loader"
        elif match_outside_strings(code, YAML_UNSAFE):
            kind = "yaml.unsafe_load"
        elif match_outside_strings(code, YAML_LOAD) and not _yaml_marked_safe(lines, index):
            kind = "yaml.load"
        if not kind:
            continue
        found.append(
            make(
                "AS-DESER",
                source.rel,
                index + 1,
                f"Untrusted data can reach {kind}.",
                line.rstrip(),
            )
        )
    return found


def _yaml_marked_safe(lines: list[str], index: int) -> bool:
    window = "\n".join(lines[index : index + 8])
    return "SafeLoader" in window or "safe_load" in window


def _crypto(source: SourceFile, lines: list[str], masked: list[bool]) -> list[Candidate]:
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line, _comment_marker(source.language))
        weak_hash = match_outside_strings(code, WEAK_HASH)
        weak_cipher = match_outside_strings(code, WEAK_CIPHER)
        if weak_hash is None and weak_cipher is None:
            continue
        if weak_hash is not None and _hash_excused(lines, index):
            continue
        nearby = "\n".join(lines[max(0, index - 6) : index + 3])
        severity = "high" if PASSWORD_WORD.search(nearby) else "medium"
        found.append(
            make(
                "AS-CRYPTO",
                source.rel,
                index + 1,
                "Weak hash or cipher.",
                line.rstrip(),
                severity=severity,
            )
        )
    return found


def _hash_excused(lines: list[str], index: int) -> bool:
    window = "\n".join(lines[index : index + 3])
    return "usedforsecurity=False" in window or "usedforsecurity = False" in window


def _tls(source: SourceFile, lines: list[str], masked: list[bool]) -> list[Candidate]:
    marker = _comment_marker(source.language)
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line, marker)
        if match_outside_strings(code, TLS_OFF) is None:
            continue
        found.append(
            make(
                "AS-TLS",
                source.rel,
                index + 1,
                "TLS certificate verification is disabled.",
                line.rstrip(),
            )
        )
    return found


def _cors(source: SourceFile, lines: list[str], masked: list[bool]) -> list[Candidate]:
    marker = _comment_marker(source.language)
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line, marker)
        header = CORS_HEADER.search(code) and "*" in code
        if not header and not CORS_ORIGIN.search(code):
            continue
        found.append(
            make(
                "AS-CORS",
                source.rel,
                index + 1,
                "CORS policy reflects every origin.",
                line.rstrip(),
            )
        )
    return found


def _debug(source: SourceFile, lines: list[str], masked: list[bool]) -> list[Candidate]:
    if source.language not in {None, "python"}:
        return []
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line)
        if match_outside_strings(code, DEBUG_RUN) is None and DEBUG_FLAG.search(code) is None:
            continue
        found.append(
            make(
                "AS-DEBUG",
                source.rel,
                index + 1,
                "Debug mode is enabled.",
                line.rstrip(),
            )
        )
    return found


def _paths(
    source: SourceFile,
    lines: list[str],
    masked: list[bool],
    tainted: list[set[str]],
) -> list[Candidate]:
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line)
        match = match_outside_strings(code, PATH_CALL)
        if match is None:
            continue
        args = _args_after(code, match.end() - 1)
        names = _names_in_args(args, tainted[index])
        if not names:
            continue
        label = ", ".join(names)
        found.append(
            make(
                "AS-PATH",
                source.rel,
                index + 1,
                f"Filesystem path includes external input ({label}).",
                line.rstrip(),
            )
        )
    return found


def _ssrf(
    source: SourceFile,
    lines: list[str],
    masked: list[bool],
    tainted: list[set[str]],
) -> list[Candidate]:
    found: list[Candidate] = []
    for index, line in enumerate(lines):
        if masked[index]:
            continue
        code = strip_comment(line)
        match = match_outside_strings(code, SSRF_CALL)
        if match is None:
            continue
        args = _args_after(code, match.end() - 1)
        names = _names_in_args(args, tainted[index])
        if not names:
            continue
        label = ", ".join(names)
        found.append(
            make(
                "AS-SSRF",
                source.rel,
                index + 1,
                f"Outbound request target includes external input ({label}).",
                line.rstrip(),
            )
        )
    return found


def _args_after(code: str, open_paren: int) -> str:
    depth = 0
    for index in range(open_paren, len(code)):
        char = code[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return code[open_paren + 1 : index]
    return code[open_paren + 1 :]


def _names_in_args(args: str, tainted: set[str]) -> list[str]:
    names: list[str] = []
    if re.search(r"\brequest\s*\.", args):
        names.append("request")
    blank = blank_strings(args)
    for name in sorted(tainted):
        if re.search(rf"\b{re.escape(name)}\b", blank):
            names.append(name)
    return names


def _comment_marker(language: str | None) -> str:
    if language in {"javascript", "typescript", "go", "rust", "java", "php"}:
        return "//"
    return "#"
