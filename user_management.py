import sqlite3 as sql
import time
import random                            # contains hash function
from email.message import EmailMessage      # Needed to Creat Email                              # make password hidden                              # Used to create a timeout for the validation code
import secrets
from datetime import datetime
import re                             # Needed to send email
import hashlib                              # contains hash function
import getpass                              # make password hidden                               # Used to create a timeout for the validation code
from cryptography.fernet import Fernet      # pip install cryptography

#this function returns the key as binary data
def load_key():
    return open("secret.key", "rb").read()

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


def is_valid_email_regex(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+$'
    # basically its allowing the characters a-z, A-Z, 0-9, ., _, %, + and - in the first one, the plus means its one or more characters, 
    # the @ means it needs an @ and then it allows the characters a-z, A-Z, 0-9, . and -
    # then it needs a dot and then some characters that are atleast 2 characters long
    if re.fullmatch(pattern, email):
        return True
    else:
        return False

#this function inserts a new line of data into the user database, containing a username, hashed password, salt and email
def insertUser(username, password, salt, email):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username,password,salt,email) VALUES (?,?,?,?)",
        (username, password, salt, email),
    )
    con.commit()
    con.close()

#this function retrieves data from the user database,
#the function checks if there are any usernames stored in the data that match with the username trying to be retrieved
#if there is, it then trys to find any usernames stored in the data that also have the password
#if it finds this then it returns True, otherwise it will return False.
def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?",(username,))
    if cur.fetchone() == None:
        con.close()
        return False
    else:
        cur.execute("SELECT * FROM users WHERE username = ? AND password = ?",(username, password,))
        if cur.fetchone() == None:
            con.close()
            return False
        else:
            con.close()
            return True

#this function retrieves the salt corresponding with the username
#the function checks if there are any usernames stored in the data that match with the username trying to be retrieved
#if so it will select the salt corresponding with that username and return that
def retrieveSalt(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?",(username,))
    if cur.fetchone() == None:
        con.close()
        return False
    else:
        cur.execute("SELECT salt FROM users WHERE username = ?",(username,))
        return cur.fetchone()[0]


    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.txt", "w")
    for row in data:
        f.write(f"{row[1]}\n")
    f.close()
    with open("templates/partials/success_feedback.txt") as f:
        feedback = [line.strip() for line in f]
    return feedback