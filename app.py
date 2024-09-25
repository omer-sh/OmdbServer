import bcrypt
from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta

app = Flask(__name__)

# MongoDB setup
client = MongoClient('mongodb://mongodb-for-omdb:00ttji0gccVUITNxqCu6NxwTlnvN5cbi034cAQ7lgabq8AojDRdJbfUpImkQBlaRJuO0jy3xwVgLACDbnAa44Q==@mongodb-for-omdb.mongo.cosmos.azure.com:10255/?ssl=true&retrywrites=false&replicaSet=globaldb&maxIdleTimeMS=120000&appName=@mongodb-for-omdb@')
db = client['OMDB']  # Replace with your actual database name


# Initialize the Blob Service Client
connection_string = "DefaultEndpointsProtocol=https;AccountName=photosforomdb;AccountKey=uiWxI5x9UWkye4P/jUjM1ZgMkRsYcKMlCjbeFyE1mDA0vkIq+6YN6qy2l2Ze5bAclwi7Xkl2Cx/R+ASt7biu0g==;EndpointSuffix=core.windows.net"
account_key = "uiWxI5x9UWkye4P/jUjM1ZgMkRsYcKMlCjbeFyE1mDA0vkIq+6YN6qy2l2Ze5bAclwi7Xkl2Cx/R+ASt7biu0g=="
blob_service_client = BlobServiceClient.from_connection_string(connection_string)
account_name = "photosforomdb"
container_name = "photos"  # Replace with your container name


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

    #remove eny sas tokens for the image so all the users will be forced to reload this image
    db.sas_tokens.delete_one({"blob_name": image_url})

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


# Utility function to generate the full blob URL with SAS token
def get_blob_url_with_sas(blob_name):
    # Check if a valid SAS token already exists in the database
    token_data = db.sas_tokens.find_one({"blob_name": blob_name})
    if token_data and token_data['expiry'] > datetime.utcnow():
        return f"{blob_name}?{token_data['sas_token']}"

    # Generate a new SAS token
    sas_token = generate_blob_sas(
        account_name=account_name,
        container_name=container_name,
        blob_name=blob_name.split("/")[-1],
        account_key=account_key,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.utcnow() + timedelta(hours=1)
    )

    # Save the new SAS token to the database only if it doesn't exist or is expired
    try:
        db.sas_tokens.update_one(
            {"blob_name": blob_name},
            {"$set": {"sas_token": sas_token, "expiry": datetime.utcnow() + timedelta(hours=1)}},
            upsert=True
        )
    except Exception as e:
        print(f"Failed to update SAS token in the database: {e}")

    # Construct the full URL with the SAS token
    return f"{blob_name}?{sas_token}"


# Get all public playlists of all users
@app.route('/get_public_playlists', methods=['GET'])
def get_public_playlists():
    playlists = db.playlists.find({"visibility": "public"})
    result = []

    for playlist in playlists:
        creator = db.users.find_one({"_id": playlist['userId']})

        result.append({
            "playlistId": str(playlist['_id']),
            "creatorName": creator['fullName'],
            "playlistName": playlist['playlistName'],
            "playlistPhoto": get_blob_url_with_sas(playlist['playlistPhoto']) if playlist['playlistPhoto'] else None,
            "numberOfMovies": len(playlist['movieIds'])
        })

    return jsonify(result), 200


# Get all playlists for a user (both private and public)
@app.route('/get_user_playlists/<user_id>', methods=['GET'])
def get_user_playlists(user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})

    if user:
        playlists = db.playlists.find({"userId": ObjectId(user_id)})
        result = []

        for playlist in playlists:
            result.append({
                "playlistId": str(playlist['_id']),
                "playlistPhoto": get_blob_url_with_sas(playlist['playlistPhoto']) if playlist["playlistPhoto"] else None,
                "playlistName": playlist['playlistName'],
                "visibility": playlist['visibility'],
                "numberOfMovies": len(playlist['movieIds'])
            })


        return jsonify(result), 200
    else:
        return jsonify({"error": "User not found"}), 404


@app.route('/get_playlist_info', methods=['GET'])
def get_playlist_info():
    playlist_id = request.args.get('playlistId')
    user_id = request.args.get('userId')

    if not playlist_id or not user_id:
        return jsonify({"error": "Missing playlistId or userId"}), 400

    playlist = db.playlists.find_one({"_id": ObjectId(playlist_id)})

    if not playlist:
        return jsonify({"error": "Playlist not found"}), 404

    if playlist['visibility'] == 'private' and str(playlist['userId']) != user_id:
        return jsonify({"error": "Unauthorized access to private playlist"}), 403

    creator = db.users.find_one({"_id": playlist['userId']})

    playlist_info = {
        "userId": str(playlist['userId']),
        "playlistId": str(playlist['_id']),
        "creatorName": creator['fullName'],
        "creatorPhoto": get_blob_url_with_sas(creator["userPhoto"]) if creator["userPhoto"] else None,
        "playlistName": playlist['playlistName'],
        "playlistPhoto": get_blob_url_with_sas(playlist['playlistPhoto']) if playlist["playlistPhoto"] else None,
        "visibility": playlist['visibility'],
        "movieIds": playlist['movieIds']
    }

    return jsonify(playlist_info), 200

# Update user information (name, photo, password)
@app.route('/update_user', methods=['POST'])
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
            if 'password' in data:
                update_fields['password'] = hash_password(data['password'])

            db.users.update_one({"_id": ObjectId(data['userId'])}, {"$set": update_fields})
            return jsonify({"message": "User's information updated successfully!"}), 200
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415


@app.route('/update_playlist', methods=['PUT'])
def update_playlist():
    if request.is_json:
        data = request.get_json()
        playlist_id = data.get('playlistId')
        user_id = data.get('userId')

        if not playlist_id or not user_id:
            return jsonify({"error": "Missing playlistId or userId"}), 400

        playlist = db.playlists.find_one({"_id": ObjectId(playlist_id)})

        if not playlist:
            return jsonify({"error": "Playlist not found"}), 404

        if str(playlist['userId']) != user_id:
            return jsonify({"error": "Unauthorized access to update playlist"}), 403

        update_fields = {}
        if 'playlistName' in data:
            update_fields['playlistName'] = data['playlistName']
        if 'playlistPhoto' in data:
            update_fields['playlistPhoto'] = data['playlistPhoto']
        if 'visibility' in data:
            update_fields['visibility'] = data['visibility']

        db.playlists.update_one({"_id": ObjectId(playlist_id)}, {"$set": update_fields})
        return jsonify({"message": "Playlist updated successfully!"}), 200
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415

@app.route('/remove_playlist', methods=['DELETE'])
def remove_playlist():
    playlist_id = request.args.get('playlistId')
    user_id = request.args.get('userId')

    if not playlist_id or not user_id:
        return jsonify({"error": "Missing playlistId or userId"}), 400

    playlist = db.playlists.find_one({"_id": ObjectId(playlist_id)})

    if not playlist:
        return jsonify({"error": "Playlist not found"}), 404

    if str(playlist['userId']) != user_id:
        return jsonify({"error": "Unauthorized access to remove playlist"}), 403

    db.playlists.delete_one({"_id": ObjectId(playlist_id)})
    return jsonify({"message": "Playlist removed successfully!"}), 200


@app.route('/update_movie_in_playlists', methods=['PUT'])
def update_movie_in_playlists():
    if request.is_json:
        data = request.get_json()
        user_id = data.get('userId')
        movie_id = data.get('movieId')
        add_playlists = data.get('addPlaylists', [])
        remove_playlists = data.get('removePlaylists', [])

        if not user_id or not movie_id:
            return jsonify({"error": "Missing userId or movieId"}), 400

        for playlist_id in add_playlists:
            playlist = db.playlists.find_one({"_id": ObjectId(playlist_id)})
            if playlist and str(playlist['userId']) == user_id:
                db.playlists.update_one({"_id": ObjectId(playlist_id)}, {"$addToSet": {"movieIds": movie_id}})

        for playlist_id in remove_playlists:
            playlist = db.playlists.find_one({"_id": ObjectId(playlist_id)})
            if playlist and str(playlist['userId']) == user_id:
                db.playlists.update_one({"_id": ObjectId(playlist_id)}, {"$pull": {"movieIds": movie_id}})

        return jsonify({"message": "Movie playlists updated!"}), 200
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415


@app.route('/get_all_user_playlists_by_movie', methods=['GET'])
def get_all_user_playlists_by_movie():
    user_id = request.args.get('userId')
    movie_id = request.args.get('movieId')

    if not user_id or not movie_id:
        return jsonify({"error": "Missing userId or movieId"}), 400

    user = db.users.find_one({"_id": ObjectId(user_id)})

    if not user:
        return jsonify({"error": "User not found"}), 404

    playlists = db.playlists.find({"userId": ObjectId(user_id)})
    result = []

    for playlist in playlists:
        result.append({
            "playlistName": playlist['playlistName'],
            "playlistId": str(playlist["_id"]),
            "containsMovie": movie_id in playlist['movieIds']
        })

    return jsonify(result), 200

def myApp(environ, start_response):
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True, use_reloader=False)

if __name__ == '__main__':
    myApp(None, None)
