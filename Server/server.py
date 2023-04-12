import zipfile

from bson import ObjectId
from flask import Flask, request, jsonify, Response, abort, make_response
from pymongo import MongoClient
from bson.binary import Binary
import io

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['FunctionID']
collection = db['fidb']
users = db['users']

# Create operation
@app.route('/create', methods=['POST'])
def create():
    data = request.json
    result = collection.insert_one(data)
    return jsonify(str(result.inserted_id))

# Register
@app.route("/register", methods=['POST'])
def register():
    payload = request.get_json()
    name = payload['username']
    hash = payload['pwdHash']

    user = users.find_one({'name': name})
    if user == None:
        users.insert_one({"name": name,"pwdHash": hash})
        return Response("Success! You can now log in with your new username and password.")
    else:
        return Response("Sorry, this username is already taken. Please choose another one.")

# Login
@app.route("/login", methods=['POST'])
def login():
    payload = request.get_json()
    name = payload['username']
    hash = payload['pwdHash']

    user = users.find_one({'name': name})  
    if user != None:
        user["_id"] = str(user['_id'])
        hashServer = user['pwdHash']
        if hash == hashServer:
            return Response("Great news! You have successfully accessed your account.\n Your id : " + user['_id'])
        return Response("Invalid username or password. Please try again.")
    return Response("Username not found. Please try again.")

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

@app.route('/download_files', methods=['GET'])
def download_files():
    files = collection.find()

    # Create an in-memory byte stream to store the zipped files
    memory_stream = io.BytesIO()

    # Create a zip file object with the in-memory byte stream
    with zipfile.ZipFile(memory_stream, mode='w') as zip_file:
        # Add each file to the zip file
        for file in files:
            file_name = file['file_name']
            file_data = file['file_data']

            # Write the file data to the zip file
            zip_file.writestr(file_name, file_data)

    # Move the stream position back to the beginning
    memory_stream.seek(0)

    # Create a Flask response with the zip file data
    response = app.response_class(memory_stream.read(), mimetype='application/zip')
    response.headers.set('Content-Disposition', 'attachment', filename='all_files.zip')

    # Close the memory stream and zip file
    memory_stream.close()
    zip_file.close()

    # Send the zip file as a response
    return response

# Read operation
@app.route('/get/<name>', methods=['GET'])
def get(name):
    client.save_file()
    data = collection.find_one({'value': name})
    data['_id'] = str(data['_id'])
    print(data)
    return data

# Update operation
@app.route('/update/<id>', methods=['PUT'])
def update(id):
    data = request.json
    result = collection.update_one({'_id': ObjectId(id)}, {'$set': data})
    return jsonify({'modified_count': result.modified_count})

# Delete operation
@app.route('/delete/<id>', methods=['DELETE'])
def delete(id):
    result = collection.delete_one({'_id': ObjectId(id)})
    return jsonify({'deleted_count': result.deleted_count})

if __name__ == '__main__':
    app.run(debug=True)
