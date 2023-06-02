import json
import os
import pymongo
from bson import ObjectId
from flask import Flask, request, Response, abort, make_response
from pymongo import MongoClient
import uuid
import datetime
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import base64

# Load environment variables from credentials.env file
env_path = 'credentials.env'
load_dotenv(env_path)

# Get email and password from environment variables
FROM_EMAIL = os.getenv('FROM_EMAIL')
PASSWORD = os.getenv('PASSWORD')

# Create Flask app
app = Flask(__name__)

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['FunctionID']
collection = db['fidb']
users = db['users']

# Registration route
@app.route("/register", methods=['POST'])
def register():
    # Retrieve the JSON payload from the request
    payload = request.get_json()
    # Extract the required data from the payload
    email = payload['username']
    hash = payload['pwdHash']
    salt = payload['salt']

    # Check if user already exists
    try:
        user = users.find_one({'email': email})
    except pymongo.errors.ConnectionFailure as e:
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    if user is not None:
        return Response("Sorry, this username is already taken. Please choose another one.")

    # Generate verification token and expiration time
    verification_token = str(uuid.uuid4())
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    # Create verification email
    recipient_email = email
    message = MIMEText(f'Hi {email}, please click the following link to verify your email address: https://glacial-springs-45246.herokuapp.com/verify_email?token={verification_token}')
    message['Subject'] = 'Verify Your Email Address'
    message['From'] = FROM_EMAIL
    message['To'] = recipient_email

    # Send verification email
    try:
        with smtplib.SMTP('send.one.com', 587) as smtp_server:
            smtp_server.starttls()
            smtp_server.login(FROM_EMAIL, PASSWORD)
            smtp_server.send_message(message)
    except Exception as e:
        return Response("Sorry, we were unable to send the verification email. Please try again later."), 500

    # Store user information in the database
    try:
        users.insert_one({
            "pwdHash": hash,
            "salt": salt,
            "email": email,
            "verification_token": verification_token,
            "verification_expiration": expiration_time
        })
    except Exception as e:
        return Response("Sorry, there was an error with the database. Please try again later."), 500

    return Response("Success! A verification email has been sent to your email address.")

# Email verification route
@app.route("/verify_email", methods=['GET'])
def verify_email():
    token = request.args.get('token')

    user = users.find_one({'verification_token': token})

    if user == None:
        return Response("Sorry, the verification link is invalid.")

    now = datetime.datetime.utcnow()
    if user['verification_expiration'] < now:
        return Response("Sorry, the verification link has expired.")

    # Remove verification token and expiration time from the user document
    users.update_one(
        {"_id": user["_id"]},
        {"$unset": {"verification_token": "", "verification_expiration": ""}}
    )

    return Response("Success! Your email address has been verified.")

# discussion route
@app.route("/discuss", methods=['POST'])
def discuss():
    payload = request.get_json()

    userto = payload['userto']
    userfrom = payload['userfrom']
    function = payload['funname'].strip()
    message_to = payload['message']

    try:
        # Retrieve the function details from the collection
        function = collection.find_one({'funName': function})
        function_decoded = base64.b64decode(function['Codec']).decode('utf-8')

        # Retrieve the user details from the users collection
        userto = users.find_one({'_id': ObjectId(userto)})
        userfrom = users.find_one({'_id': ObjectId(userfrom)})
    except pymongo.errors.ConnectionFailure as e:
        # Handle any database connection error
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    if userto is None:
        # Check if the user doesn't exist
        return Response("The user doesn't exist")

    # Extract the recipient's and sender's email addresses
    recipient_email = userto["email"]
    email_from = userfrom["email"]

    # Construct the email message
    message = MIMEText(f'Hi, {email_from} wants to discuss with you about your function: {function_decoded} \nHere is their message: {message_to}')
    message['Subject'] = 'Discussion Request'
    message['From'] = FROM_EMAIL
    message['To'] = recipient_email

    try:
        # Connect to the SMTP server and send the email
        with smtplib.SMTP('send.one.com', 587) as smtp_server:
            smtp_server.starttls()
            smtp_server.login(FROM_EMAIL, PASSWORD)
            smtp_server.send_message(message)
    except Exception as e:
        # Handle any error that occurs while sending the email
        return Response("Sorry, we were unable to send the email. Please try again later.")

    # Return a success response
    return Response("Success! An email has been sent to user.")

# report route
@app.route("/report", methods=['POST'])
def report():
    payload = request.get_json()
    userto = payload['userto']
    userfrom = payload['userfrom']
    function = payload['funname'].strip()

    try:
        # Retrieve the function details from the collection
        function = collection.find_one({'funName': function})
        function_decoded = base64.b64decode(function['Codec']).decode('utf-8')

        # Retrieve the user details from the users collection
        userto = users.find_one({'_id': ObjectId(userto)})
        userfrom = users.find_one({'_id': ObjectId(userfrom)})
    except pymongo.errors.ConnectionFailure as e:
        # Handle any database connection error
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    if userto is None:
        # Check if the user doesn't exist
        return Response("The user doesn't exist")

    # Extract the recipient's and sender's email addresses
    recipient_email = userto["email"]
    email_from = userfrom["email"]

    # Construct the email message
    message = MIMEText(f'{email_from} wants to report: {recipient_email} about their function: {function_decoded}')
    message['Subject'] = 'Report Request'
    message['From'] = FROM_EMAIL
    message['To'] = FROM_EMAIL

    try:
        # Connect to the SMTP server and send the email
        with smtplib.SMTP('send.one.com', 587) as smtp_server:
            smtp_server.starttls()
            smtp_server.login(FROM_EMAIL, PASSWORD)
            smtp_server.send_message(message)
    except Exception as e:
        # Handle any error that occurs while sending the email
        return Response("Sorry, we were unable to send the email. Please try again later.")

    # Return a success response
    return Response("Success! An email has been sent to user.")

# Login route
@app.route("/get_salt", methods=['POST'])
def get_salt():
    payload = request.get_json()
    email = payload['username']

    # Find the user document with the provided email
    user = users.find_one({'email': email})

    if "verification_token" in user:
        # Check if the user's email address is not verified
        return Response("You didn't verify your email address")

    # Construct the salt and password hash string
    salt_and_pwd_hash = f"{user['salt']},{user['pwdHash']},{user['_id']}"

    # Return the salt and password hash as a response
    return Response(salt_and_pwd_hash)

# push route
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
    comment = payload['comment']

    if not user_name:
        # Return a response indicating no connected user
        response = make_response(f"No connected user", 409)
        return response

    try:
        user = users.find_one({'_id':  ObjectId(user_name)})
    except pymongo.errors.ConnectionFailure as e:
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    # If 0 functions or not connected user
    if len(funName) <= 0 or user is None:
        abort(404)

    if funName:
        existing_file = collection.find_one({"funName": funName})
        if existing_file:
            if confirm == "1":
                # Insert the function details into the collection
                collection.insert_one({
                    "user": user_name,
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
                    "comment": comment,
                })

                return Response("Function '" + funName + "' uploaded successfully.")

            print("Existe deja")
            # Return a response indicating the function already exists in the database
            response = make_response(f"Function '" + funName + "' already exists in the database.", 409)
            response.headers['funName'] = existing_file['funName']
            return response

        # Insert the function details into the collection
        collection.insert_one({
            "user": user_name,
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
            "comment": comment,
        })

        return Response("Function '" + funName + "' uploaded successfully.")


# Pull route
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
            item["Codec"],
            item["comment"]
        ]
        # Join the fields with commas and add a newline character
        csv_data.append(item_data)
    print(csv_data)
    # Return the CSV data as a plain text response
    return Response(json.dumps(csv_data), mimetype='text/plain')

@app.route('/get_remove/<id>', methods=['GET'])
def get_remove(id):
    try:
        # Retrieve all documents in the collection where the "user" field matches the provided `id`
        cursor = collection.find({"user": id})
    except pymongo.errors.ConnectionFailure as e:
        # Handle connection failure with the database
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500
    # Create an empty list to store the signatures of the functions
    list = []
    for document in cursor:
        # Append the "signature" field of each document to the list
        list.append(document["signature"])

    return str(list)

@app.route("/delete_selected", methods=['POST'])
def delete_selected():
    payload = request.get_json()
    function = payload['item'].strip()
    try:
        # Delete the document from the collection where the "signature" field matches the provided `function`
        collection.delete_one({'signature': function})
    except pymongo.errors.ConnectionFailure as e:
        # Handle connection failure with the database
        return Response("Sorry, there was an error with the database connection. Please try again later."), 500

    return Response("Success! Function has been deleted")
if __name__ == '__main__':
    app.run(debug=True)
