"""User-facing failures that should exit 2."""


class AuditError(RuntimeError):
    """The audit could not run. The message is safe to print."""
