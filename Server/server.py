import json
import os
import zipfile

from bson import ObjectId, json_util
from flask import Flask, request, jsonify, Response, abort, make_response
from pymongo import MongoClient
from bson.binary import Binary
import io
import uuid
import datetime
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import base64


env_path = 'credentials.env'
load_dotenv(env_path)

FROM_EMAIL = os.getenv('FROM_EMAIL')
PASSWORD = os.getenv('PASSWORD')

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['FunctionID']
collection = db['fidb']
users = db['users']

@app.route("/register", methods=['POST'])
def register():
    payload = request.get_json()
    email = payload['username']
    hash = payload['pwdHash']
    salt = payload['salt']

    print(email)
    user = users.find_one({'email': email})
    if user != None:
        return Response("Sorry, this username is already taken. Please choose another one.")

    verification_token = str(uuid.uuid4())
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    recipient_email = email
    message = MIMEText(f'Hi {email}, please click the following link to verify your email address: http://127.0.0.1:5000/verify_email?token={verification_token}')
    message['Subject'] = 'Verify Your Email Address'
    message['From'] = FROM_EMAIL
    print(FROM_EMAIL)
    message['To'] = recipient_email

    try:
        with smtplib.SMTP('send.one.com', 587) as smtp_server:
            smtp_server.starttls()
            smtp_server.login(FROM_EMAIL, PASSWORD)
            smtp_server.send_message(message)
    except Exception as e:
        return Response("Sorry, we were unable to send the verification email. Please try again later.")

    users.insert_one({
        "pwdHash": hash,
        "salt": salt,
        "email": email,
        "verification_token": verification_token,
        "verification_expiration": expiration_time
    })
    return Response("Success! A verification email has been sent to your email address.")


@app.route("/verify_email", methods=['GET'])
def verify_email():
    token = request.args.get('token')
    user = users.find_one({'verification_token': token})
    if user == None:
        return Response("Sorry, the verification link is invalid.")

    now = datetime.datetime.utcnow()
    if user['verification_expiration'] < now:
        return Response("Sorry, the verification link has expired.")

    users.update_one(
        {"_id": user["_id"]},
        {"$unset": {"verification_token": "", "verification_expiration": ""}}
    )

    return Response("Success! Your email address has been verified.")

@app.route("/discuss", methods=['POST'])
def discuss():
    payload = request.get_json()
    userto = payload['userto']
    userfrom = payload['userfrom']

    userto = users.find_one({'_id': ObjectId(userto)})
    userfrom = users.find_one({'_id': ObjectId(userfrom)})

    if userto == None:
        return Response("the user doesn't exist")

    recipient_email = userto["email"]
    email_from = userfrom["email"]
    message = MIMEText(f'Hi {recipient_email}, {email_from} want to discuss with you about your function.')
    message['Subject'] = 'discussion request'
    message['From'] = FROM_EMAIL
    message['To'] = recipient_email

    try:
        with smtplib.SMTP('send.one.com', 587) as smtp_server:
            smtp_server.starttls()
            smtp_server.login(FROM_EMAIL, PASSWORD)
            smtp_server.send_message(message)
    except Exception as e:
        return Response("Sorry, we were unable to send the email. Please try again later.")

    return Response("Success! An email has been sent to his email address.")

@app.route("/report", methods=['POST'])
def report():
    payload = request.get_json()
    userto = payload['userto']
    userfrom = payload['userfrom']

    userto = users.find_one({'_id': ObjectId(userto)})
    userfrom = users.find_one({'_id': ObjectId(userfrom)})

    if userto == None:
        return Response("the user doesn't exist")

    recipient_email = userto["email"]
    email_from = userfrom["email"]
    print(email_from)
    print(recipient_email)
    message = MIMEText(f'Hi, {email_from} want to report : {recipient_email}')
    print(message)
    message['Subject'] = 'report request'
    message['From'] = FROM_EMAIL
    message['To'] = FROM_EMAIL

    try:
        with smtplib.SMTP('send.one.com', 587) as smtp_server:
            smtp_server.starttls()
            smtp_server.login(FROM_EMAIL, PASSWORD)
            smtp_server.send_message(message)
    except Exception as e:
        return Response("Sorry, we were unable to send the email. Please try again later.")

    return Response("Success! An email has been sent to his email address.")

# Login
@app.route("/get_salt", methods=['POST'])
def get_salt():
    payload = request.get_json()
    email = payload['username']

    user = users.find_one({'email': email})

    if "verification_token" in user:
        return Response("You didnt verify your email address")

    salt_and_pwd_hash = f"{user['salt']},{user['pwdHash']},{user['_id']}"
    return Response(salt_and_pwd_hash)

# Add files to DB (push)
@app.route("/file", methods=['POST'])
def file_push():
    file_data = b""
    while True:
        chunk = request.stream.read(4096)
        if not chunk:
            break
        file_data += chunk

    file_name = request.headers.get('X-File-Name')
    user_name = request.headers.get('Username')
    user = users.find_one({'_id':  ObjectId(user_name)})
    print(user)
    print(request.headers)
    # If others try to send wrong file or not connected user
    if len(file_data) <= 0 or user == None:
        abort(404)
    if file_name:
        if not file_name.endswith(".fidb"):
            file_name += ".fidb"

        existing_file = collection.find_one({"file_name": file_name})
        if existing_file:
            response = make_response(f"File '{file_name}' already exists in the database.", 409)
            response.headers['user_name'] = existing_file['user']
            return response

        collection.insert_one({"file_name": file_name, "file_data": Binary(file_data),"user":user_name})
        return f"File '{file_name}' uploaded successfully."
    else:
        collection.insert_one({"file_data": Binary(file_data)})
        return "File uploaded successfully."

@app.route("/send_file", methods=['POST'])
def file_send():

    user_name = request.headers.get('Unique-Id')
    library_name = request.headers.get('Libraryfamilyname')
    library_version = request.headers.get('Libraryversion')
    library_variant = request.headers.get('Libraryvariant')
    language_id = request.headers.get('Languageid')
    function_hash = request.headers.get('Codec')
    function_decoded = base64.b64decode(function_hash).decode('utf-8')

    par_position = function_decoded.find(")") + 1
    function_name = function_decoded[:par_position].lstrip()

    brack_position = function_decoded.find("{")
    code_without_name = function_decoded[brack_position:].rstrip()
    hash_code_only = base64.b64encode(code_without_name.encode('utf-8')).decode('utf-8')
    print(hash_code_only)

    user = users.find_one({'_id':  ObjectId(user_name)})
    # If others try to send wrong file or not connected user
    if len(function_hash) <= 0 or user == None:
        abort(404)
    if hash_code_only:
        existing_file = collection.find_one({"function_hash": hash_code_only})
        if existing_file:
            print("Existe deja")
            response = make_response(f"Function already exists in the database.", 409)
            response.headers['function_hash'] = existing_file['function_hash']
            return response

        collection.insert_one({"user":user_name,
                               "library_name": library_name,
                               "library_version": library_version,
                               "library_variant": library_variant,
                               "language_id": language_id,
                               "function_name": function_name,
                               "function_hash": hash_code_only,
                               })
        return Response("Function uploaded successfully.")
    else:
        collection.insert_one({"function_hash": hash_code_only})
        return "File uploaded successfully."

@app.route('/download_files', methods=['GET'])
def download_files():
    data = list(collection.find())

    # Create an empty string to store the CSV data
    csv_data = ""

    # Iterate through the data and retrieve each desired field from each item
    for item in data:
        item_data = [
            item["user"],
            item["library_name"],
            item["library_version"],
            item["library_variant"],
            item["language_id"],
            item["function_name"],
            item["function_hash"]
        ]
        # Join the fields with commas and add a newline character
        csv_data += ",".join(item_data) + ";"

    print(csv_data)
    # Return the CSV data as a plain text response
    return Response(csv_data, mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=True)
