from logging import debug

import bcrypt
import traceback
from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)

# MongoDB setup
client = MongoClient('mongodb://mongodb-for-omdb:00ttji0gccVUITNxqCu6NxwTlnvN5cbi034cAQ7lgabq8AojDRdJbfUpImkQBlaRJuO0jy3xwVgLACDbnAa44Q==@mongodb-for-omdb.mongo.cosmos.azure.com:10255/?ssl=true&retrywrites=false&replicaSet=globaldb&maxIdleTimeMS=120000&appName=@mongodb-for-omdb@')
db = client['OMDB']  # Replace with your actual database name


# Initialize the Blob Service Client
connection_string = "DefaultEndpointsProtocol=https;AccountName=photosforomdb;AccountKey=uiWxI5x9UWkye4P/jUjM1ZgMkRsYcKMlCjbeFyE1mDA0vkIq+6YN6qy2l2Ze5bAclwi7Xkl2Cx/R+ASt7biu0g==;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connection_string)


def upload_image(file):
    container_name = "photos"  # Your container name
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=file.filename)

    # Upload the file
    blob_client.upload_blob(file, overwrite=True)  # Overwrite if the blob already exists

    # Generate the URL to the uploaded blob
    return blob_client.url


@app.route('/upload', methods=['POST'])
def upload():
    if 'image' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['image']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Call the upload function
    image_url = upload_image(file)

    # Return the URL or save it to your database as needed
    return jsonify({"image_url": image_url}), 200

# Hash password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

# Verify password
def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

@app.route('/register_user', methods=['POST'])
def register_user():
    if request.is_json:
        data = request.get_json()

        # Check if the username already exists
        existing_user = db.users.find_one({"username": data['username']})
        if existing_user:
            return jsonify({"error": "Username already exists"}), 409

        hashed_password = hash_password(data['password'])
        user = {
            "username": data['username'],
            "password": hashed_password,
            "userPhoto": data['userPhoto'],
            "fullName": data['fullName']
        }

        result = db.users.insert_one(user)
        user_id = str(result.inserted_id)
        return jsonify({'userId': user_id, 'message': 'User registered successfully!'}), 201
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415

# User login with password verification
@app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        data = request.get_json()
        user = db.users.find_one({"username": data['username']})

        if user:
            if verify_password(user['password'], data['password']):
                user_id = str(user['_id'])
                return jsonify({
                    'userId': user_id,
                    'fullName': user['fullName'],
                    'userPhoto': user['userPhoto'],
                    'message': 'Login successful!'
                }), 200
            else:
                return jsonify({"error": "Invalid password"}), 401
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415

# Create playlist with visibility option
@app.route('/create_playlist', methods=['POST'])
def create_playlist():
    if request.is_json:
        data = request.get_json()

        playlist = {
            "userId": ObjectId(data['userId']),
            "playlistName": data['playlistName'],
            "playlistPhoto": data['playlistPhoto'],
            "visibility": data['visibility'],  # Can be 'public' or 'private'
            "movieIds": []
        }

        result = db.playlists.insert_one(playlist)
        playlist_id = str(result.inserted_id)
        return jsonify({'playlistId': playlist_id, 'message': 'Playlist created successfully!'}), 201
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415

# Add a movie to a playlist
@app.route('/add_movie_to_playlist', methods=['PUT'])
def add_movie_to_playlist():
    if request.is_json:
        data = request.get_json()

        playlist = db.playlists.find_one({"_id": ObjectId(data['playlistId'])})
        if playlist and playlist['userId'] == ObjectId(data['userId']):
            db.playlists.update_one({"_id": ObjectId(data['playlistId'])}, {"$addToSet": {"movieIds": data['movieId']}})
            return jsonify({"message": "Movie added to playlist!"}), 200
        else:
            return jsonify({"error": "Unauthorized or playlist not found"}), 404
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415

# Get all playlists for a user (both private and public)
@app.route('/get_user_playlists/<user_id>', methods=['GET'])
def get_user_playlists(user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})

    if user:
        playlists = db.playlists.find({"userId": ObjectId(user_id)})
        result = []
        for playlist in playlists:
            result.append({
                "playlistName": playlist['playlistName'],
                "playlistPhoto": playlist['playlistPhoto'],
                "visibility": playlist['visibility']
            })
        return jsonify(result), 200
    else:
        return jsonify({"error": "User not found"}), 404

# Get all public playlists of all users
@app.route('/get_public_playlists', methods=['GET'])
def get_public_playlists():
    playlists = db.playlists.find({"visibility": "public"})
    result = []
    for playlist in playlists:
        creator = db.users.find_one({"_id": playlist['userId']})
        result.append({
            "creatorName": creator['fullName'],
            "playlistName": playlist['playlistName'],
            "playlistPhoto": playlist['playlistPhoto']
        })
    return jsonify(result), 200

# Update user information (name, photo)
@app.route('/update_user', methods=['PUT'])
def update_user():
    if request.is_json:
        data = request.get_json()
        user = db.users.find_one({"_id": ObjectId(data['userId'])})

        if user:
            update_fields = {}
            if 'fullName' in data:
                update_fields['fullName'] = data['fullName']
            if 'userPhoto' in data:
                update_fields['userPhoto'] = data['userPhoto']

            db.users.update_one({"_id": ObjectId(data['userId'])}, {"$set": update_fields})
            return jsonify({"message": "User's information updated successfully!"}), 200
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415

def myApp(environ, start_response):
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True, use_reloader=False)

if __name__ == '__main__':
    myApp(None, None)
