############################# Set up ###########################################
# Import Flask dependencies
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import os
# Import Spotify dependencies
import spotipy
from spotipy.oauth2 import SpotifyOAuth, SpotifyClientCredentials
from spotipy.cache_handler import FlaskSessionCacheHandler
import pandas as pd
from datetime import date
import random
import time
import json
from urllib.parse import urlencode
import requests
from datetime import datetime, timedelta
import random as rand
import string as string
import base64
# Access environment variables
s_id = os.getenv("SECRET_KEY")
c_id = os.getenv("API_KEY")
jwt_key = os.getenv("JWT_KEY")
my_id = os.getenv("MY_ID")
redirect_uri = "http://64.23.182.26:5000/callback"
scope = "user-library-read playlist-modify-private" 
redirect_code = "AQA81Yf0r3U-arbbm8po2U_15PhTEFbVPJf2E3kRe3Dxys6OXi9q3EQSe2VV5N4dSYALFvEw6can7XLB0K_Dst-nkZCBCG2H2XD5k4z7ZqPzsHapT5nMDe-ChCq0-K1UrNnaULQjBqJ35uoeL8UWcD9TV3EectlmRS4OxnlMTIonQkc4tmhJfExMSwJxPp06RZCHut4nxY-oCCo2e9hINhJYccyg9Mes2oL-GNE"



# Spotify OAuth2 Manager
def get_spotify_oauth():
    return SpotifyOAuth(
        client_id=c_id,
        client_secret=s_id,
        redirect_uri=redirect_uri,
        scope=scope
    )

# Set SpotiFire ID
me = my_id

# Spotify API rate limiter
sleep_rate=5

# Initialize app
app = Flask(__name__)
app.secret_key = '12345678910'
# CORS(app)
CORS(app, resources={r"/*": {"origins": "http://64.23.182.26:5000"}}, supports_credentials=True)

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

# Initialize Spotipy with Client Credentials Flow
def initialize_spotipy():
    return spotipy.Spotify(auth_manager=SpotifyClientCredentials(client_id=c_id, client_secret=s_id))

################################# Routes ####################################################

@app.route('/authorize')
def authorize():
    state_key = createStateKey(15)
    session['state_key'] = state_key
    
    authorize_url = 'https://accounts.spotify.com/en/authorize'
    parameters = {
        'response_type': 'code',
        'client_id': c_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'state': state_key
    }
    response = make_response(redirect(authorize_url + '?' + urlencode(parameters)))
    
    return response
def createStateKey(size):
    #https://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits
    return ''.join(rand.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(size))
@app.route('/callback')
def callback():
    if request.args.get('state') != session['state_key']:
        return render_template('home.html', error='State verification failed.')
    
    if request.args.get('error'):
        return render_template('home.html', error='Spotify authorization error.')
    
    code = request.args.get('code')
    session.pop('state_key', None)  # Clear state_key after successful verification
    
    token_payload = getToken(code)
    if token_payload is None:
        return render_template('home.html', error='Failed to fetch access token.')
    
    session['token'] = token_payload[0]
    session['refresh_token'] = token_payload[1]
    session['token_expiration'] = time.time() + token_payload[2]
    
    current_user = getUserInformation(session)
    session['user_id'] = current_user['id']
    
    return redirect('/home')

def makeGetRequest(session, url, params={}):
    headers = {"Authorization": "Bearer {}".format(session['token'])}
    response = requests.get(url, headers=headers, params=params)

    # 200 code indicates request was successful
    if response.status_code == 200:
        return response.json()

    # if a 401 error occurs, update the access token
    elif response.status_code == 401 and checkTokenStatus(session) is not None:
        return makeGetRequest(session, url, params)
    else:
        return None

def checkTokenStatus(session):
    if time.time() > session['token_expiration']:
        payload = refreshToken(session['refresh_token'])

        if payload is not None:
            session['token'] = payload[0]
            session['token_expiration'] = time.time() + payload[1]
        else:
            return None

    return "Success"

def getUserInformation(session):
    url = 'https://api.spotify.com/v1/me'
    payload = makeGetRequest(session, url)

    if payload is None:
        return None

    return payload

def refreshToken(refresh_token):
    auth_str = f"{c_id}:{s_id}"
    auth_bytes = auth_str.encode('utf-8')
    auth_base64 = base64.b64encode(auth_bytes).decode('utf-8')
    token_url = 'https://accounts.spotify.com/api/token'
    authorization = f"Basic {auth_base64}"

    headers = {
        'Authorization': authorization,
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    body = {
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token'
    }
    post_response = requests.post(token_url, headers=headers, data=body)

    # 200 code indicates access token was properly granted
    if post_response.status_code == 200:
        return post_response.json()['access_token'], post_response.json()['expires_in']
    else:
        return None

def getToken(code):
    auth_str = f"{c_id}:{s_id}"
    auth_bytes = auth_str.encode('utf-8')
    auth_base64 = base64.b64encode(auth_bytes).decode('utf-8')

    token_url = 'https://accounts.spotify.com/api/token'
    authorization = f"Basic {auth_base64}"
    headers = {
        'Authorization': authorization,
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    body = {
        'code': code,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    post_response = requests.post(token_url, headers=headers, data=body)
    if post_response.status_code == 200:
        pr = post_response.json()
        return pr['access_token'], pr['refresh_token'], pr['expires_in']
    else:
        return None

# # Endpoint for Spotify authorization flow
# @app.route('/authorize')
# def authorize():
#     # Construct Spotify authorization URL
#     spotify_authorize_url = 'https://accounts.spotify.com/authorize'
#     params = {
#         'client_id': 'b089443f5b9043f68eb7349713db606e',
#         'response_type': 'code',
#         'redirect_uri': 'http://64.23.182.26:1410/callback',
#         'scope': 'user-library-read playlist-modify-private'
#     }
#     spotify_auth_url = spotify_authorize_url + '?' + urlencode(params)
    
#     # Redirect to Spotify authorization URL
#     return redirect(spotify_auth_url)

# # Endpoint to handle Spotify authorization callback
# @app.route('/callback')
# def callback():
#     sp_oauth = get_spotify_auth_manager()
#     code = request.args.get('code')

#     try:
#         token_info = sp_oauth.get_access_token(code)
#         # Optionally save token_info to cache or database securely
#         if token_info:
#             sp_oauth.cache_handler.save_token_to_cache(token_info)
#             return jsonify({'success': 'Token saved to cache'}), 200
#         else:
#             return jsonify({'error': 'Failed to get token'}), 400

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
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
# Create playlist route
@app.route('/create', methods=['POST'])
@jwt_required(optional=True)
def create_playlist():
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        token_info = getToken()
        sp = initialize_spotipy(token_info)
        
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

            # Log playlist creation details
            print(f"Playlist created: ID - {playlist_id}, URL - {playlist_url}")

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
