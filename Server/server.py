from bson import ObjectId
from flask import Flask, request, jsonify
from pymongo import MongoClient

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