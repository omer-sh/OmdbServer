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

# Create watch list with visibility option
@app.route('/create_watch_list', methods=['POST'])
def create_watch_list():
    if request.is_json:
        data = request.get_json()

        watch_list = {
            "userId": ObjectId(data['userId']),
            "watchListName": data['watchListName'],
            "watchListPhoto": data['watchListPhoto'],
            "visibility": data['visibility'],  # Can be 'public' or 'private'
            "movieIds": []
        }

        result = db.watch_lists.insert_one(watch_list)
        watch_list_id = str(result.inserted_id)
        return jsonify({'watchListId': watch_list_id, 'message': 'watch list created successfully!'}), 201
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


# Get all public watch lists of all users
@app.route('/get_public_watch_lists', methods=['GET'])
def get_public_watch_lists():
    watch_lists = db.watch_lists.find({"visibility": "public"})
    result = []

    for watch_list in watch_lists:
        creator = db.users.find_one({"_id": watch_list['userId']})

        result.append({
            "watchListId": str(watch_list['_id']),
            "creatorName": creator['fullName'],
            "watchListName": watch_list['watchListName'],
            "watchListPhoto": get_blob_url_with_sas(watch_list['watchListPhoto']) if watch_list['watchListPhoto'] else None,
            "numberOfMovies": len(watch_list['movieIds'])
        })

    return jsonify(result), 200


# Get all watch lists for a user (both private and public)
@app.route('/get_user_watch_lists/<user_id>', methods=['GET'])
def get_user_watch_lists(user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})

    if user:
        watch_lists = db.watch_lists.find({"userId": ObjectId(user_id)})
        result = []

        for watch_list in watch_lists:
            result.append({
                "watchListId": str(watch_list['_id']),
                "watchListPhoto": get_blob_url_with_sas(watch_list['watchListPhoto']) if watch_list["watchListPhoto"] else None,
                "watchListName": watch_list['watchListName'],
                "visibility": watch_list['visibility'],
                "numberOfMovies": len(watch_list['movieIds'])
            })


        return jsonify(result), 200
    else:
        return jsonify({"error": "User not found"}), 404


@app.route('/get_watch_list_info', methods=['GET'])
def get_watch_list_info():
    watch_list_id = request.args.get('watchListId')
    user_id = request.args.get('userId')

    if not watch_list_id:
        return jsonify({"error": "Missing watchListId"}), 400

    watch_list = db.watch_lists.find_one({"_id": ObjectId(watch_list_id)})

    if not watch_list:
        return jsonify({"error": "Playlist not found"}), 404

    if watch_list['visibility'] == 'private' and str(watch_list['userId']) != user_id:
        return jsonify({"error": "Unauthorized access to private watch list"}), 403

    creator = db.users.find_one({"_id": watch_list['userId']})

    watch_list_info = {
        "userId": str(watch_list['userId']),
        "watchListId": str(watch_list['_id']),
        "creatorName": creator['fullName'],
        "creatorPhoto": get_blob_url_with_sas(creator["userPhoto"]) if creator["userPhoto"] else None,
        "watchListName": watch_list['watchListName'],
        "watchListPhoto": get_blob_url_with_sas(watch_list['watchListPhoto']) if watch_list["watchListPhoto"] else None,
        "visibility": watch_list['visibility'],
        "movieIds": watch_list['movieIds']
    }

    return jsonify(watch_list_info), 200

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


@app.route('/update_watch_list', methods=['PUT'])
def update_watch_list():
    if request.is_json:
        data = request.get_json()
        watch_list_id = data.get('watchListId')
        user_id = data.get('userId')

        if not watch_list_id or not user_id:
            return jsonify({"error": "Missing watchListId or userId"}), 400

        watch_list = db.watch_lists.find_one({"_id": ObjectId(watch_list_id)})

        if not watch_list:
            return jsonify({"error": "Playlist not found"}), 404

        if str(watch_list['userId']) != user_id:
            return jsonify({"error": "Unauthorized access to update watch list"}), 403

        update_fields = {}
        if 'watchListName' in data:
            update_fields['watchListName'] = data['watchListName']
        if 'watchListPhoto' in data:
            update_fields['watchListPhoto'] = data['watchListPhoto']
        if 'visibility' in data:
            update_fields['visibility'] = data['visibility']

        db.watch_lists.update_one({"_id": ObjectId(watch_list_id)}, {"$set": update_fields})
        return jsonify({"message": "Playlist updated successfully!"}), 200
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415

@app.route('/remove_watch_list', methods=['DELETE'])
def remove_watch_list():
    watch_list_id = request.args.get('watchListId')
    user_id = request.args.get('userId')

    if not watch_list_id or not user_id:
        return jsonify({"error": "Missing watchListId or userId"}), 400

    watch_list = db.watch_lists.find_one({"_id": ObjectId(watch_list_id)})

    if not watch_list:
        return jsonify({"error": "Playlist not found"}), 404

    if str(watch_list['userId']) != user_id:
        return jsonify({"error": "Unauthorized access to remove watch list"}), 403

    db.watch_lists.delete_one({"_id": ObjectId(watch_list_id)})
    return jsonify({"message": "Playlist removed successfully!"}), 200


@app.route('/update_movie_in_watch_lists', methods=['PUT'])
def update_movie_in_watch_lists():
    if request.is_json:
        data = request.get_json()
        user_id = data.get('userId')
        movie_id = data.get('movieId')
        add_watch_lists = data.get('addWatchLists', [])
        remove_watch_lists = data.get('removeWatchLists', [])

        if not user_id or not movie_id:
            return jsonify({"error": "Missing userId or movieId"}), 400

        for watch_list_id in add_watch_lists:
            watch_list = db.watch_lists.find_one({"_id": ObjectId(watch_list_id)})
            if watch_list and str(watch_list['userId']) == user_id:
                db.watch_lists.update_one({"_id": ObjectId(watch_list_id)}, {"$addToSet": {"movieIds": movie_id}})

        for watch_list_id in remove_watch_lists:
            watch_list = db.watch_lists.find_one({"_id": ObjectId(watch_list_id)})
            if watch_list and str(watch_list['userId']) == user_id:
                db.watch_lists.update_one({"_id": ObjectId(watch_list_id)}, {"$pull": {"movieIds": movie_id}})

        return jsonify({"message": "Movie watch lists updated!"}), 200
    else:
        return jsonify({"error": "Unsupported Media Type"}), 415


@app.route('/get_all_user_watch_lists_by_movie', methods=['GET'])
def get_all_user_watch_lists_by_movie():
    user_id = request.args.get('userId')
    movie_id = request.args.get('movieId')

    if not user_id or not movie_id:
        return jsonify({"error": "Missing userId or movieId"}), 400

    user = db.users.find_one({"_id": ObjectId(user_id)})

    if not user:
        return jsonify({"error": "User not found"}), 404

    watch_lists = db.watch_lists.find({"userId": ObjectId(user_id)})
    result = []

    for watch_lists in watch_lists:
        result.append({
            "watchListName": watch_lists['watchListName'],
            "watchListId": str(watch_lists["_id"]),
            "containsMovie": movie_id in watch_lists['movieIds']
        })

    return jsonify(result), 200

@app.route('/')
def hello():
    return "Hello, HTTPS!"

def myApp(environ, start_response):
    app.run()

if __name__ == '__main__':
    myApp(None, None)
