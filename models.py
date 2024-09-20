class User:
    def __init__(self, username, password, user_photo, full_name):
        self.username = username
        self.password = password
        self.user_photo = user_photo
        self.full_name = full_name

    def to_dict(self):
        return {
            'username': self.username,
            'password': self.password,
            'userPhoto': self.user_photo,
            'fullName': self.full_name
        }

class Playlist:
    def __init__(self, playlist_name, movie_ids, playlist_photo):
        self.playlist_name = playlist_name
        self.movie_ids = movie_ids
        self.playlist_photo = playlist_photo

    def to_dict(self):
        return {
            'playlistName': self.playlist_name,
            'movieIds': self.movie_ids,
            'playlistPhoto': self.playlist_photo
        }
