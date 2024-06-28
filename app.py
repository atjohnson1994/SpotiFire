############################# Set up ###########################################
# Import Flask dependencies
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import os
# Import Spotify dependencies
import spotipy
from spotipy.oauth2 import SpotifyOAuth
from spotipy.cache_handler import CacheHandler
import pandas as pd
from datetime import date
import random
import time
import json


# Access environment variables
s_id = os.getenv("SECRET_KEY")
c_id = os.getenv("API_KEY")
jwt_key = os.getenv("JWT_KEY")
my_id = os.getenv("MY_ID")
redirect_uri = "http://64.23.182.26:1410/"
scope = "user-library-read playlist-modify-private" 
class CustomCacheHandler(CacheHandler):
    def __init__(self):
        super().__init__()
        self.cache_path = '.spotipy_oauth_token.cache'  # Change this to your cache file path if needed
        print(f'Initializing CustomCacheHandler with cache path: {self.cache_path}')

    def get_cached_token(self):
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, 'r') as f:
                    token_info = json.load(f)
                    print(f'Cached token retrieved: {token_info}')
                    return token_info
            print('No cached token found.')
            return None
        except Exception as e:
            print(f'Error reading cache file: {e}')
            return None

    def save_token_to_cache(self, token_info):
        try:
            with open(self.cache_path, 'w') as f:
                json.dump(token_info, f)
            print(f'Token saved to cache: {token_info}')
        except Exception as e:
            print(f'Error writing to cache file: {e}')

# SpotifyOAuth initialization
def get_spotify_auth_manager():
    print("Initializing SpotifyOAuth")
    return SpotifyOAuth(
        client_id=c_id,
        client_secret=s_id,
        redirect_uri=redirect_uri,
        cache_handler=CustomCacheHandler(),
        scope=scope
    )
# # Get the authorization URL
# auth_url = auth_manager.get_authorize_url()


# # Exchange the authorization code for an access token
# token_info = auth_manager.get_access_token(code)

# # Use the auth_manager with Spotipy to make API requests
# sp = spotipy.Spotify(auth_manager=auth_manager)

# Set SpotiFire ID
me = my_id

# Spotify API rate limiter
sleep_rate=5

# Initialize app
app = Flask(__name__)
# CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Configure your JWT
app.config['JWT_SECRET_KEY'] = jwt_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///items.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set up database
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    playlist_uri = db.Column(db.String(200), nullable=True)
    playlist_url = db.Column(db.String(200), nullable=True)
    songs_per_listener = db.Column(db.Integer, nullable=False)
    explicit = db.Column(db.Boolean, nullable=False)
    holiday = db.Column(db.Boolean, nullable=False)
    number_of_related_artists = db.Column(db.Integer, nullable=False)
    related_artist_songs_count = db.Column(db.Integer, nullable=False)

# Item model
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    selected = db.Column(db.Boolean, nullable=False)
    a1 = db.Column(db.String(120), nullable=True)
    a2 = db.Column(db.String(120), nullable=True)
    a3 = db.Column(db.String(120), nullable=True)
    a4 = db.Column(db.String(120), nullable=True)
    a5 = db.Column(db.String(120), nullable=True)
    a6 = db.Column(db.String(120), nullable=True)
    a7 = db.Column(db.String(120), nullable=True)
    a8 = db.Column(db.String(120), nullable=True)
    a9 = db.Column(db.String(120), nullable=True)
    a10 = db.Column(db.String(120), nullable=True)

# Create the database and tables
with app.app_context():
    db.create_all()

################################# Routes ####################################################
# Endpoint for Spotify authorization flow
@app.route('/spotify/login')
def spotify_login():
    auth_manager = get_spotify_auth_manager()
    auth_url = auth_manager.get_authorize_url()
    return jsonify({'auth_url': auth_url})

# Endpoint to handle Spotify authorization callback
@app.route('/spotify/callback')
def spotify_callback():
    code = request.args.get('code')
    auth_manager = get_spotify_auth_manager()
    token_info = auth_manager.get_access_token(code)
    # Optionally, save token_info in session or database for further use
    return jsonify(token_info)
### Login ###
# User login route to authenticate and return a JWT token
# Route for the login page (GET request)
@app.route('/login', methods=['GET'])
def login_form():
    return render_template('login.html')

# Route for handling login form submissions (POST request)
@app.route('/login', methods=['POST'])
def login_submit():
    data = request.get_json()
    username = data.get('username', None)
    password = data.get('password', None)
    if not username or not password:
        return jsonify({'msg': 'Missing username or password'}), 400
    
    # User query
    user = User.query.filter_by(username=username).first()

    # Check password and provide jwt token
    if not user or not check_password_hash(user.password, password):
        return jsonify({'msg': 'Bad username or password'}), 401
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

### Register ###
# Register route
@app.route('/register', methods=['GET'])
def register_form():
    return render_template('register.html')

# User registration route
@app.route('/register', methods=['POST'])
def register_submit():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if User.query.filter_by(username=username).first():
        return jsonify({'msg': 'Username already exists'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, explicit=1, holiday=0, songs_per_listener=30, number_of_related_artists=3, related_artist_songs_count=1)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'msg': 'User created successfully'}), 201

### Home ###
# Home route
@app.route('/home', methods=['GET', 'POST', 'DELETE'])
@jwt_required(optional=True)
def home_get():
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()
        items = Item.query.filter_by(user_id=user_id).all()

        if user:
            # User is authenticated
            content = {'username': user.username, 'playlist_url': user.playlist_url, 'songs_per_listener': user.songs_per_listener, 'explicit': user.explicit, 'holiday': user.holiday, 'number_of_related_artists': user.number_of_related_artists, 'related_artist_songs_count': user.related_artist_songs_count}
            listeners = [{'id': item.id, 'name': item.name, 'selected': item.selected,
                          'a1': item.a1, 'a2': item.a2, 'a3': item.a3, 
                          'a4': item.a4, 'a5': item.a5, 'a6': item.a6, 
                          'a7': item.a7, 'a8': item.a8, 'a9': item.a9, 
                          'a10': item.a10} for item in items]
        else:
            # User is not authenticated
            content = {'message': 'Welcome, guest!'}
            listeners = []  # No items for guests

        # Construct the response JSON
        response_json = {'content': content, 'listeners': listeners}

        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify(response_json), 200
        else:
            return render_template('home.html', content=content)

    except Exception as e:
        return jsonify({"message": "Error processing request", "error": str(e)}), 500

### Select/Unselect ###
# Selected route (from 'create playlist' modal)
@app.route('/update-listeners', methods=['POST'])
@jwt_required()
def update_listeners():
    try:
        user_id = get_jwt_identity() # Get user ID
        user = User.query.filter_by(id=user_id).first() # Query user ID in database
        if not user: # If user isn't found
            return jsonify({"message": "User not found"}), 404 # Error message
        data = request.json # Hold JSON response
        listeners = data.get('listeners', []) # Extract listeners from response
        print(f"Received data: {listeners}") # Log successful receibt of response
        updated_item_ids = [] # Clear id list

        # Query all listeners for user, update selected status, commit changes to database
        for listener in listeners: # For each listener 
            print(f"Processing listener: {listener}") # Log attempt to update listener
            item = Item.query.filter_by(id=listener['id'], user_id=user_id).first() # Query database for listener ID
            if item: # If listener is found
                print(f"Found item: {item.id}, updating selected to {listener['selected']}") # Log that listener was found
                item.selected = listener['selected'] # Update listener selection
                db.session.add(item) # Add changes to listener
                updated_item_ids.append(item.id) # Add listener id to list
            else: # If no listener is found
                print(f"Item with id {listener['id']} not found for user {user_id}") # Error message
        db.session.commit() # Commit changes to database
        print("Database commit successful") # Log successful database update
        
        # Verify changes
        updated_items = Item.query.filter(Item.id.in_(updated_item_ids)).all() # Query all updated listeners
        print("Updated items in database:", [(item.id, item.selected) for item in updated_items]) # Log the attempt   
        return jsonify({"message": "Listeners updated successfully"}), 200
    except Exception as e:
        print("Error processing request:", str(e))
        db.session.rollback()
        return jsonify({"message": "Error processing request", "error": str(e)}), 500

### Landing ###
# Landing page route
@app.route('/')
def landing():
    return render_template('landing.html')

# Get all listeners for the active user
@app.route('/listeners', methods=['GET'])
@jwt_required()
def get_user_items():
    user_id = get_jwt_identity()
    items = Item.query.filter_by(user_id=user_id).all() # Query all listeners for the user
    if items: # If listeners are found
        return jsonify([{'id': item.id, 'name': item.name} for item in items]) # Return JSON response with all listeners
    else: # If no listeners are found
        return jsonify({'error': 'No items found for this user'}), 404 # Error message

### Add Listener ###
# Route to add a new listener
@app.route('/items', methods=['POST'])
@jwt_required()
def add_item():
    # Retrieve data from JSON payload sent in the request
    data = request.json
    
    # Get user ID from the JWT token
    user_id = get_jwt_identity()
    
    # Create a new Item object with the retrieved data
    new_item = Item(
        name=data['name'],
        user_id=user_id,
        selected=1,
        a1=data['a1'],
        a2=data.get('a2'),  # These fields will default to None if not provided in JSON
        a3=data.get('a3'),
        a4=data.get('a4'),
        a5=data.get('a5'),
        a6=data.get('a6'),
        a7=data.get('a7'),
        a8=data.get('a8'),
        a9=data.get('a9'),
        a10=data.get('a10')
    )
    
    # Add the new item to the database session and commit
    db.session.add(new_item)
    db.session.commit()
    
    # Return a JSON response with the newly added item's details and HTTP status code 201 (Created)
    return jsonify({'id': new_item.id, 'name': new_item.name}), 201

# # Route to get username
# @app.route('/user', methods=['GET'])
# @jwt_required()
# def get_user():
#     user_id = get_jwt_identity()
#     user = User.query.filter_by(id=user_id).first()

#     if not user:
#         return jsonify({"message": "User not found"}), 404

#     return jsonify(username=user.username)

### Settings ###
# Route to update user settings
@app.route('/settings', methods=['POST'])
@jwt_required()
def update_settings():
    # Retrieve data from JSON payload sent in the request
    data = request.json
    # Get user ID from the JWT token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Update user settings based on data from JSON payload
    user.songs_per_listener = data.get('spl', user.songs_per_listener)  # Update only if 'spl' is present in data
    user.explicit = data.get('explicit', user.explicit)
    user.holiday = data.get('holiday', user.holiday)
    user.number_of_related_artists = data.get('nra', user.number_of_related_artists)
    user.related_artist_songs_count = data.get('rasc', user.related_artist_songs_count)

    # Commit changes to the database
    db.session.commit()
    
    return jsonify({'message': 'User settings updated successfully'}), 200

### Remove Listener ###
# Route to remove listener
@app.route('/items/<string:item_name>', methods=['DELETE'])
@jwt_required()
def delete_item(item_name):
    # Get user ID from the JWT token
    user_id = get_jwt_identity()

    # Query the database for the item to delete based on user_id and item_name
    item_to_delete = Item.query.filter_by(name=item_name, user_id=user_id).first()

    if not item_to_delete:
        return jsonify({'message': 'Item not found or you are not authorized to delete it'}), 404

    try:
        # Delete the item from the database
        db.session.delete(item_to_delete)
        db.session.commit()

        # Return a success message
        return jsonify({'message': 'Item deleted successfully'}), 200

    except Exception as e:
        # Handle database or other errors
        db.session.rollback()
        return jsonify({'message': 'Failed to delete item', 'error': str(e)}), 500

### Create Playlist ###
# Route to create a new playlist
@app.route('/create', methods=['GET'])
@jwt_required()
def create_playlist():
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404
        print('1 - User found')

        sp_oauth = get_spotify_auth_manager()
        print('2 - SpotifyOAuth initialized')

        token_info = sp_oauth.get_cached_token()
        if token_info is None:
            print('3 - No token found')
            return jsonify({'error': 'No token found'}), 401

        print(f'3 - Token found: {token_info}')
        
        access_token = token_info.get('access_token')
        if not access_token:
            print('3.1 - No access token in token info')
            return jsonify({'error': 'Invalid token info'}), 401

        print(f'3.2 - Access token: {access_token}')
        
        sp = spotipy.Spotify(auth=access_token)
        print('4 - Spotify client initialized')
        

        if user.playlist_uri:
            user_uri = user.playlist_uri
            playlist_url = user.playlist_url
        else:
            # Create a new playlist if user does not have one
            playlist = sp.user_playlist_create(user=me, name=f"{user.username}'s Playlist", public=False, collaborative=False, description='')
            playlist_id = playlist['id']
            sp.playlist_change_details(playlist_id, collaborative=True)
            user_uri = playlist['uri']
            playlist_url = playlist['external_urls']['spotify']
            user.playlist_uri = user_uri
            user.playlist_url = playlist_url
            db.session.commit()

        # Fetch items for playlist creation
        items = Item.query.filter_by(user_id=user_id, selected=True).all()

        if items:
            # Call your playlist creation function
            playlist_creation(items, user, sp)
            return jsonify({'playlist_url': playlist_url}), 200
        else:
            return jsonify({'error': 'No items found for this user'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# @app.route('/splogin')
# def login():
#     auth_url = sp_oauth.get_authorize_url()
#     return redirect(auth_url)

######################################## Functions #############################################
# Add songs to spotify playlist
def add_songs_to_playlist(all_songs, user_uri, sp):
    split_index = 0
    while split_index < len(all_songs):
        split = all_songs[split_index:split_index + 99]
        if split_index == 0:
            sp.playlist_replace_items(playlist_id=user_uri, items=split)
        else:
            sp.playlist_add_items(playlist_id=user_uri, items=split, position=None)
        time.sleep(sleep_rate)
        split_index += 99

# SpotiFire
def playlist_creation(items, user, sp):
    all_songs = []
    holiday_key_words = ['christmas', 'santa']

    for i in range(len(items)):
        item = items[i]
        user_uri = user.playlist_uri
        allow_explicit = user.explicit
        allow_holiday = user.holiday
        spl = user.songs_per_listener
        nra = user.number_of_related_artists
        rasc = user.related_artist_songs_count
        songs = []
        artists = [
            item.a1, item.a2, item.a3, item.a4, item.a5, 
            item.a6, item.a7, item.a8, item.a9, item.a10
        ]
        artists_clean = pd.Series(artists).dropna().reset_index(drop=True)

        for t in range(len(artists_clean)):
            artist_name = artists_clean[t]
            search_results = sp.search(q='artist:' + artist_name, type='artist', limit=1)
            if search_results['artists']['total'] == 0:
                print(f"No results for {artist_name}")
                continue
            print(f"Searching {artist_name}'s related artists")
            time.sleep(sleep_rate)
            artist_uri = search_results['artists']['items'][0]['uri']
            related_artist_search_results = sp.artist_related_artists(artist_uri)
            related_artists = related_artist_search_results['artists'][:nra]
            samples = []
            for related_artist in related_artists:
                uri = related_artist['uri']
                top_tracks = sp.artist_top_tracks(uri, country='US')
                time.sleep(sleep_rate)
                samples.extend(random.sample(top_tracks['tracks'], min(rasc, len(top_tracks['tracks']))))
            artist_top_songs = sp.artist_top_tracks(artist_uri, country='US')['tracks']
            samples.extend(artist_top_songs)

            for track in samples:
                if not allow_holiday and any(keyword in track['name'].lower() for keyword in holiday_key_words):
                    print(f"Track '{track['name']}' by {track['artists'][0]['name']} removed for Holiday status.")
                    continue
                if not allow_explicit and track['explicit']:
                    print(f"Track '{track['name']}' by {track['artists'][0]['name']} removed for explicit rating.")
                    continue
                print(f"Track '{track['name']}' by {track['artists'][0]['name']} added to sample pool.")
                songs.append(track['uri'])

        if len(songs) < spl:
            if len(songs) > 2:
                filler_artist = related_artists[0]['uri']
                filler_top_tracks = sp.artist_top_tracks(filler_artist, country='US')['tracks']
                filler_tracks = random.sample(filler_top_tracks, min(3, len(filler_top_tracks)))
                for track in filler_tracks:
                    if not allow_explicit and track['explicit']:
                        print(f"Track '{track['name']}' by {track['artists'][0]['name']} removed for explicit rating.")
                        continue
                    if not allow_holiday and any(keyword in track['name'].lower() for keyword in holiday_key_words):
                        print(f"Track '{track['name']}' by {track['artists'][0]['name']} removed for Holiday status.")
                        continue
                    songs.append(track['uri'])
                    print(f"Track '{track['name']}' by {track['artists'][0]['name']} added to sample pool.")
        else:
            songs = random.sample(songs, spl)
        all_songs.extend(songs)
    add_songs_to_playlist(all_songs, user_uri, sp)
  



if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)