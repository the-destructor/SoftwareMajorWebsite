from flask import Flask, url_for, redirect, request, render_template, abort, session
import user_management as dbHandler
import random                               # Generates Random numbers
import hashlib                              # contains hash function
from email.message import EmailMessage      # Needed to Creat Email
import getpass                              # make password hidden
import time                                 
import sqlite3
from datetime import datetime
import re
from cryptography.fernet import Fernet
import secrets

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


def generate_and_save_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]
app.jinja_env.globals["csrf_token"] = generate_csrf_token

def validate_token():
    token = session.get("csrf_token")
    form_token = request.form.get("csrf_token")

    if not token or token != form_token:
        abort(400)

def encrypt_message(message_text):
    key = load_key()
    encoded_message = message_text.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message

def decrypt_message(encrypted_message_text):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message_text)
    return decrypted_message.decode()

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

@app.route("/logout", methods=["POST", "GET"])
def logout():
    try:
        if request.method == "GET" and request.args.get("url"):
                   url = request.args.get("url", "")
                   return redirect(url, code=302)
        if request.method == "POST":
            validate_token()
            session.clear()
            return redirect(url_for("home"))
        else:
            return render_template("logout.html")
        
    except:
        print("error in logout")
        return render_template("logout.html")
    

@app.route("/login", methods=["POST", "GET"])
def login():
    try:
        if session.get("logged_in"):
            print("User is logged in:", session["username"])
            return redirect(url_for("logout"))
        if request.method == "GET" and request.args.get("url"):
            url = request.args.get("url", "")
            return redirect(url, code=302)
        if request.method == "POST":
            validate_token()
            username = request.form["username"]
            password = request.form["password"]
            hashed_password = hash_password(password, dbHandler.retrieveSalt(username))
            isLoggedIn = dbHandler.retrieveUsers(username, hashed_password)
            session["username"] = username
            session["logged_in"] = isLoggedIn
            if isLoggedIn:
                return redirect(url_for("home"))
            else:
                return render_template("login.html")
        else:
            return render_template("login.html")
    except:
        print("error in login")
        return render_template("login.html")


@app.route("/signup", methods=["POST", "GET"])
def signup():
    try:
        if session.get("logged_in"):
            print("User is logged in:", session["username"])
        if request.method == "GET" and request.args.get("url"):
            url = request.args.get("url", "")
            return redirect(url, code=302)
        if request.method == "POST":
            validate_token()
            username = request.form["username"]
            password = request.form["password"]
            if not is_strong_password(password):
                return render_template("signup.html")
            new_email = encrypt_message(request.form["email"])
            new_salt = secrets.token_hex(16)
            hashed_password = hash_password(password, new_salt)
            dbHandler.insertUser(username, hashed_password, new_salt, new_email)
            session["username"] = username
            session["logged_in"] = True
            return redirect("/")
        else:
            return render_template("signup.html")
    except:
        print("error in signup")
        return render_template("signup.html")

@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
    try:
        if session.get("logged_in"):
            print("User is logged in:", session["username"])
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

    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
