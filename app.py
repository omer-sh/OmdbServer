import bcrypt
from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId

app = Flask(__name__)

# MongoDB setup
client = MongoClient('mongodb+srv://omerremo12345:Tn3gHhS130qhJp2Y@cluster0.fvwtd.mongodb.net/')  # Replace with your actual MongoDB connection string
db = client['OMDB']  # Replace with your actual database name



# Hash password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

# Verify password
def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

# Register user with hashed password, full name, and photo
@app.route('/register_user', methods=['POST'])
def register_user():
    if request.is_json:
        data = request.get_json()

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


if __name__ == '__main__':
    app.run(debug=True)
