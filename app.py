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


#this function generates an encryption key and writes it into the secret.key file
def generate_and_save_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    return open("secret.key", "rb").read()

#this function generates a csrf token if there isn't one in the session and then stores it in the session.
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]
app.jinja_env.globals["csrf_token"] = generate_csrf_token

#this function checks if the tokens from the form is the correct token, to prevent Cross-site request forgery.
def validate_token():
    token = session.get("csrf_token")
    form_token = request.form.get("csrf_token")

    if not token or token != form_token:
        abort(400)

#this function encrypts the string using the saved key.
def encrypt_message(message_text):
    key = load_key()
    encoded_message = message_text.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message

#this function decrypts the string using the saved key.
def decrypt_message(encrypted_message_text):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message_text)
    return decrypted_message.decode()

#this function checks if the string contains these characters and has a length above 8
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


#this function combines two strings and runs them through a hashlib which hashes them.
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

#This is the log out page, it renders the log out template and runs the function
# when the user presses the submit button on the form the request method will be POST so 
# it will clear the session cache and refresh the page which effectively logs out the user
# it will then redirect to the home page.
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

@app.route("/game", methods=["GET"])
def load_game():
    try:
        if request.method == "GET" and request.args.get("url"):
                   url = request.args.get("url", "")
                   return redirect(url, code=302)
        else:
            game_title = request.args.get('game_title')
            game_file_location = request.args.get('location')
            description = load_description(sanitize_title(game_title))
            return render_template("game.html", gameTitle = game_title, gameFileLocation = game_file_location, description = description)
        
    except:
        print("error in load game")
        return render_template("index.html")

#loads the description file for the game and returns it
def load_description(name):
    path = f"descriptions/{name}.txt"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "No description available."

def sanitize_title(title):
    title = title.lower()
    # Lowercase, remove spaces, remove non‑alphanumeric characters
    cleaned = re.sub(r'[^a-z0-9]', '', title.replace(" ", ""))
    return cleaned

#makes it so \n is replaced with a <br> which makes it so my text files have line breaks
@app.template_filter('nl2br')
def nl2br(value):
    return value.replace('\n', '<br>')

@app.route("/search")
def search():
    try:
        return render_template("search.html")
            
    except:
        print("error in search")
        return render_template("search.html")

#This is the log in page, it renders the log in template and runs the function
# when the user presses the submit button on the form the request method will be POST so 
# it will check if the username and password match up with an account by asking the
# dbHandler file to run a function that checks, the dbHandler file is called user_management.py
# if the user successfully logs in it will store that in the session and redirect to the home page.
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

##Runs the sign up method and renders the sign up html template, 
# when the user presses the submit button on the form the request method will be POST so it will check if the username
# , email, and password are valid and then securely store the details via user_management.py by 
# hashing and salting the password and encrypting every other piece of user data
# , it will then redirect the page back to the home page.
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


##Runs the home method and renders the index html template, 
# like every other template, if the session token is invalid it will abort the webpage.
@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["GET"])
def home():
    try:
        if session.get("logged_in"):
            print("User is logged in:", session["username"])
        if request.method == "GET" and request.args.get("url"):
            url = request.args.get("url", "")
            return redirect(url, code=302)
        else:
            return render_template("index.html")
    except:
        print("error in index")
        return render_template("index.html")

if __name__ == "__main__":

    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
