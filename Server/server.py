import json
import os
import zipfile

import pymongo
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
    try:
        user = users.find_one({'email': email})
    except pymongo.errors.ConnectionFailure as e:
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    if user is not None:
        return Response("Sorry, this username is already taken. Please choose another one.")

    verification_token = str(uuid.uuid4())
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    recipient_email = email
    message = MIMEText(f'Hi {email}, please click the following link to verify your email address: https://glacial-springs-45246.herokuapp.com/verify_email?token={verification_token}')
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
        return Response("Sorry, we were unable to send the verification email. Please try again later."), 500

    try:
        users.insert_one({
            "pwdHash": hash,
            "salt": salt,
            "email": email,
            "verification_token": verification_token,
            "verification_expiration": expiration_time
        })
    except Exception as e:
        print("oh shit")
        return Response("Sorry, there was an error with the database. Please try again later."), 500

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
    function = payload['funname'].strip()

    try :
        function = collection.find_one({'funName': function})
        function_decoded = base64.b64decode(function['Codec']).decode('utf-8')
        userto = users.find_one({'_id': ObjectId(userto)})
        userfrom = users.find_one({'_id': ObjectId(userfrom)})
    except pymongo.errors.ConnectionFailure as e:
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    if userto == None:
        return Response("the user doesn't exist")

    recipient_email = userto["email"]
    email_from = userfrom["email"]
    message = MIMEText(f'Hi, {email_from} want to discuss with you about your function : {function_decoded}')
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
    function = payload['funname'].strip()

    try:
        function = collection.find_one({'funName': function})
        function_decoded = base64.b64decode(function['Codec']).decode('utf-8')
        userto = users.find_one({'_id': ObjectId(userto)})
        userfrom = users.find_one({'_id': ObjectId(userfrom)})
    except pymongo.errors.ConnectionFailure as e:
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    if userto == None:
        return Response("the user doesn't exist")

    recipient_email = userto["email"]
    email_from = userfrom["email"]
    print(email_from)
    print(recipient_email)
    message = MIMEText(f'{email_from} want to report : {recipient_email} about his function : {function_decoded}')
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

@app.route("/fid", methods=['POST'])
def receivefid():
    payload = request.get_json()
    user_name = payload['unique_id']
    confirm = payload['confirm']
    codeUnitSize = payload['codeUnitSize']
    fullHash = payload['fullHash']

    specificHashAdditionalSize = payload['specificHashAdditionalSize']
    specificHash = payload['specificHash']

    library_name = payload['libraryFamilyName']
    library_version = payload['libraryVersion']
    library_variant = payload['libraryVariant']

    Ghidraversion = payload['ghidraVersion']
    Languageid = payload['languageID']
    Languageversion = payload['languageVersion']
    Languageminorversion = payload['languageMinorVersion']
    Compilerspecid = payload['compilerSpecID']
    funName = payload['funName']
    Entrypoint = payload['entryPoint']
    signature = payload['signature']

    Codec = payload['codeC']
    
    if not(user_name):
        response = make_response(f"No connected user", 409)
        return response
    try:
        user = users.find_one({'_id':  ObjectId(user_name)})
    except pymongo.errors.ConnectionFailure as e:
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500
    # If others try to send wrong file or not connected user
    if len(funName) <= 0 or user == None:
        abort(404)
    print(request.headers)

    if funName:
        existing_file = collection.find_one({"funName": funName})
        if existing_file:
            if confirm=="1":
                collection.insert_one({"user":user_name,
                               
                               "codeUnitSize": codeUnitSize,
                               "fullHash": fullHash,
                               "specificHashAdditionalSize": specificHashAdditionalSize,
                               "specificHash": specificHash,
                               
                               "library_name": library_name,
                               "library_version": library_version,
                               "library_variant": library_variant,

                               "Ghidraversion": Ghidraversion,
                               "Languageversion": Languageversion,
                               "Languageminorversion": Languageminorversion,
                               "Compilerspecid": Compilerspecid,
                               "Entrypoint": Entrypoint,
                               "Languageid": Languageid,
                               "funName": funName,
                               "signature": signature,
                               "Codec": Codec,
                               })
                return Response("Function '" +funName+ "' uploaded successfully.")

            print("Existe deja")
            response = make_response(f"Function '" + funName + "' already exists in the database.", 409)
            response.headers['funName'] = existing_file['funName']
            return response

        collection.insert_one({"user":user_name,
                               
                               "codeUnitSize": codeUnitSize,
                               "fullHash": fullHash,
                               "specificHashAdditionalSize": specificHashAdditionalSize,
                               "specificHash": specificHash,
                               
                               "library_name": library_name,
                               "library_version": library_version,
                               "library_variant": library_variant,

                               "Ghidraversion": Ghidraversion,
                               "Languageversion": Languageversion,
                               "Languageminorversion": Languageminorversion,
                               "Compilerspecid": Compilerspecid,
                               "Entrypoint": Entrypoint,
                               "Languageid": Languageid,
                               "funName": funName,
                               "signature": signature,
                               "Codec": Codec,
                               })
        return Response("Function '" +funName+ "' uploaded successfully.")
    # else:
        # collection.insert_one({"Hashquad": Hashquad})
        # return "File uploaded successfully."

@app.route('/download_files', methods=['GET'])
def download_files():
    try:
        data = list(collection.find())
    except pymongo.errors.ConnectionFailure as e:
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    # Create an empty string to store the CSV data
    csv_data = []

    # Iterate through the data and retrieve each desired field from each item
    for item in data:
        item_data = [
           item["user"],

            item["codeUnitSize"],
            item["fullHash"],
            item["specificHashAdditionalSize"],
            item["specificHash"],

            item["library_name"],
            item["library_version"],
            item["library_variant"],
            
            item["Ghidraversion"],
            item["Languageversion"],
            item["Languageminorversion"],
            item["Compilerspecid"],
            item["Entrypoint"],
            item["Languageid"],
            item["funName"],
            item["signature"],
            item["Codec"]
        ]
        # Join the fields with commas and add a newline character
        csv_data.append(item_data)
    print(csv_data)
    # Return the CSV data as a plain text response
    return Response(json.dumps(csv_data), mimetype='text/plain')

@app.route('/get_remove/<id>', methods=['GET'])
def get_remove(id):
    try:
        cursor = collection.find({"user": id})
    except pymongo.errors.ConnectionFailure as e:
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    list = []
    for document in cursor:
        list.append(document["funName"])

    return str(list)

@app.route("/delete_selected", methods=['POST'])
def delete_selected():
    payload = request.get_json()
    function = payload['item'].strip()
    try:
        collection.delete_one({'funName': function})
    except pymongo.errors.ConnectionFailure as e:
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    return Response("Success! Function has been deleted")
if __name__ == '__main__':
    app.run(debug=True)
