from bson import ObjectId
from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.binary import Binary
import io
import os

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
        return "Registered to DB"
    else:
        return "User already exists"

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
            return "Logged in : " + user["_id"]
        return 'Incorrect login'
    return 'Not registered'

@app.route("/file", methods=['POST'])
def file_push():
    file_data = b""
    while True:
        chunk = request.stream.read(4096)
        if not chunk:
            break
        file_data += chunk
    file_name = request.headers.get('X-File-Name')
    if file_name:
        if not file_name.endswith(".fidb"):
            file_name += ".fidb"
        collection.insert_one({"file_name": file_name, "file_data": Binary(file_data)})
        return f"File '{file_name}' uploaded successfully."
    else:
        collection.insert_one({"file_data": Binary(file_data)})
        return "File uploaded successfully."

@app.route('/get/<file_name>', methods=['GET'])
def get_file(file_name):
    file_doc = collection.find_one({"file_name": "test.fidb"})
    if file_doc is None:
        return "File not found in database"
    else:
        # Get the file name and binary data from the database
        file_name = file_doc['file_name']
        file_data = file_doc['file_data']

        # Read the binary data into a BytesIO object
        file_data = io.BytesIO(file_data)

        # Save the file to disk
        with open(os.path.join(os.getcwd(), file_name), 'wb') as f:
            f.write(file_data.getbuffer())

# Read operation
@app.route('/get/<name>', methods=['GET'])
def get(name):
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
