from flask import Flask, url_for, redirect, request, render_template

import random                               # Generates Random numbers
import hashlib                              # contains hash function
from email.message import EmailMessage      # Needed to Creat Email
import getpass                              # make password hidden
import time                                 
import sqlite3
from datetime import datetime
import re

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; object-src 'none';"
    return response


def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()


@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
    try:
        if request.method == "GET" and request.args.get("url"):
            url = request.args.get("url", "")
            return redirect(url, code=302)
        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]
        else:
            return render_template("index.html")
    except:
        print("error in index")
        return render_template("index.html")

if __name__ == "__main__":

    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
