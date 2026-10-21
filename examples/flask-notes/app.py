"""Field notes service. Intentionally insecure sample. Do not deploy."""

import hashlib
import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, request, send_file
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "field-notes-signing-key-91c"
API_TOKEN = "sk-live-fieldnotes-demo-7Q"
CORS(app, resources={r"/*": {"origins": "*"}})


def _db():
    import sqlite3

    return sqlite3.connect("notes.db")


@app.route("/notes")
def list_notes():
    owner = request.args.get("owner", "")
    query = f"SELECT id, body FROM notes WHERE owner = '{owner}'"
    rows = _db().execute(query).fetchall()
    return {"notes": [{"id": row[0], "body": row[1]} for row in rows]}


@app.route("/notes/import", methods=["POST"])
def import_notes():
    notes = pickle.loads(request.data)
    return {"imported": len(notes)}


@app.route("/notes/spec", methods=["POST"])
def apply_spec():
    spec = yaml.load(request.data, Loader=yaml.Loader)
    return {"title": spec.get("title")}


@app.route("/files/<path:name>")
def download(name):
    return send_file(os.path.join("/var/fieldnotes", name))


@app.route("/preview")
def preview():
    target = request.args.get("url", "")
    response = requests.get(target, verify=False, timeout=10)
    return {"body": response.text, "token": API_TOKEN}


@app.route("/convert", methods=["POST"])
def convert():
    filename = request.form.get("filename", "")
    subprocess.run(f"convert {filename} out.pdf", shell=True, check=False)
    return {"ok": True}


@app.route("/login", methods=["POST"])
def login():
    password = request.form.get("password", "")
    digest = hashlib.md5(password.encode()).hexdigest()
    return {"digest": digest}


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    return {"value": eval(expr)}


if __name__ == "__main__":
    app.run(debug=True)
