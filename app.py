from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

# Spotify imports
import spotipy
from spotipy.oauth2 import SpotifyOAuth
import pandas as pd
from datetime import date
import random
import time

# Spotify setup
from spotifire_id import *
sp = spotipy.Spotify(auth_manager=SpotifyOAuth(client_id=c_id,
                                               client_secret=s_id,
                                               redirect_uri="http://localhost:1410/",
                                               scope=("user-library-read", "playlist-modify-private")))
me = my_id

# Playlist IDs
playlist1_uid = p1_uid
playlist2_uid = p2_uid
playlist3_uid = p3_uid
playlist4_uid = p4_uid
playlist_combo_uid = pc_uid
playlist_combo2_uid = pc2_uid

app = Flask(__name__)
# CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Configure your JWT
app.config['JWT_SECRET_KEY'] = jwt_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///items.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    # Handle login form submission logic here
    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'msg': 'Bad username or password'}), 401
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200


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
            listeners = [{'id': item.id, 'name': item.name, 
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


# Public route example
@app.route('/')
def landing():
    return render_template('landing.html')

# Route to get all items (requires authentication)
@app.route('/items', methods=['GET'])
@jwt_required()
def get_items():
    items = Item.query.all()
    return jsonify([{'id': item.id, 'name': item.name} for item in items])

# Route to get a specific item by ID (requires authentication)
@app.route('/items/<int:item_id>', methods=['GET'])
@jwt_required()
def get_item(item_id):
    item = Item.query.get(item_id)
    if item:
        return jsonify({'id': item.id, 'name': item.name})
    else:
        return jsonify({'error': 'Item not found'}), 404

# Route to get all items for the user
@app.route('/listeners', methods=['GET'])
@jwt_required()
def get_user_items():
    user_id = get_jwt_identity()
    items = Item.query.filter_by(user_id=user_id).all()
    if items:
        return jsonify([{'id': item.id, 'name': item.name} for item in items])
    else:
        return jsonify({'error': 'No items found for this user'}), 404

@app.route('/update_listener/<int:listener_id>', methods=['POST'])
def update_listener(listener_id):
    selected = request.json.get('selected')
    for listener in Item:
        if listener['id'] == listener_id:
            listener['selected'] = selected
            break
    return jsonify({'success': True})

# Route to add a new item (requires authentication)
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

@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify(username=user.username)



# Route to update an item (requires authentication)
@app.route('/items/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_item(item_id):
    item = Item.query.get(item_id)
    if not item:
        return jsonify({'error': 'Item not found'}), 404

    name = request.json.get('name', None)
    item.name = name
    db.session.commit()
    return jsonify({'id': item.id, 'name': item.name})

# Route to update user settings (requires authentication)
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

# Add songs to playlist
def add_songs_to_playlist(all_songs, user_uri):
    split_index = 0
    while split_index < len(all_songs):
        split = all_songs[split_index:split_index + 99]
        if split_index == 0:
            sp.playlist_replace_items(playlist_id=user_uri, items=split)
        else:
            sp.playlist_add_items(playlist_id=user_uri, items=split, position=None)
        time.sleep(6)
        split_index += 99

def playlist_creation(items, user):
    all_songs = []
    for i in range(len(items)):
        # Key words used to filter out holiday music
        holiday_key_words = ['Christmas','christmas','Santa','santa']
        item = items[i]
        name = item.name
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
        # Clean the artist list
        artists_clean = pd.Series(artists).dropna().reset_index(drop=True)

        # Loop through artist list
        for t in range(len(artists_clean)):
            artist_name = artists_clean[t]
            search_results = sp.search(q='artist:' + artist_name, type='artist', limit=1)
            if search_results['artists']['total'] == 0: # If no artists found
                print(f"No results for {artist_name}") # Print message
                continue # Skip
            print(f"Searching {artist_name}'s related artists")
            time.sleep(6)

            # Collect URI's
            artist_uri = search_results['artists']['items'][0]['uri']
            related_artist_search_results = sp.artist_related_artists(artist_uri) # Search related artists
            related_artist_uri1 = related_artist_search_results['artists'][0]['uri']
            related_artist_uri2 = related_artist_search_results['artists'][1]['uri']
            related_artist_uri3 = related_artist_search_results['artists'][2]['uri']

            # Collect top tracks for each artist
            artist_top_songs = sp.artist_top_tracks(artist_uri,country='US')
            related_artist_top_songs1 = sp.artist_top_tracks(related_artist_uri1, country='US')
            print(f'Related artist 1: {related_artist_search_results["artists"][0]["name"]}')
            time.sleep(6)
            related_artist_top_songs2 = sp.artist_top_tracks(related_artist_uri2, country='US')
            print(f'Related artist 2: {related_artist_search_results["artists"][1]["name"]}')
            time.sleep(6)
            related_artist_top_songs3 = sp.artist_top_tracks(related_artist_uri3, country='US')
            print(f'Related artist 3: {related_artist_search_results["artists"][2]["name"]}')
            time.sleep(6)

            # Randomly select one song from each related artist
            related_artist_top_songs_sample1 = random.sample(related_artist_top_songs1['tracks'],rasc)
            related_artist_top_songs_sample2 = random.sample(related_artist_top_songs2['tracks'],rasc)
            related_artist_top_songs_sample3 = random.sample(related_artist_top_songs3['tracks'],rasc)

            # Filter out explicit and holiday tracks
            sample_lists = [related_artist_top_songs_sample1, related_artist_top_songs_sample2, related_artist_top_songs_sample3] # List of sampled tracks
            for sample in sample_lists:
                for j in range(len(sample)):
                  if allow_holiday == False:
                      if sample[j]['name'] in holiday_key_words: # Check for holiday track
                          print(f"Track '{sample[j]['name']}' by {sample[j]['artists'][0]['name']} removed for Holiday status.")
                          continue
                  if allow_explicit == False:
                      if sample[j]['explicit'] == False: # Check for explicit
                          print(f"Track '{sample[j]['name']}' by {sample[j]['artists'][0]['name']} added to sample pool.")
                          songs.append(sample[j]['uri'])
                      else:
                          print(f"Track '{sample[j]['name']}' by {sample[j]['artists'][0]['name']} removed for explicit rating.")
                  else:
                      print(f"Track '{sample[j]['name']}' by {sample[j]['artists'][0]['name']} added to sample pool.")
                      songs.append(sample[j]['uri'])
                    
                    

            for j in range(len(artist_top_songs['tracks'])):
                if artist_top_songs['tracks'][j]['name'] in holiday_key_words: # Check for holiday track
                    print(f"Track '{artist_top_songs['tracks'][j]['name']}' by {artist_top_songs['tracks'][j]['artists'][0]['name']} removed for Holiday status.")
                    continue
                if artist_top_songs['tracks'][j]['explicit'] == False: # Check for explicit
                    print(f"Track '{artist_top_songs['tracks'][j]['name']}' by {artist_top_songs['tracks'][j]['artists'][0]['name']} added to sample pool.")
                    songs.append(artist_top_songs['tracks'][j]['uri'])
                else:
                    print(f"Track '{artist_top_songs['tracks'][j]['name']}' by {artist_top_songs['tracks'][j]['artists'][0]['name']} removed for explicit rating.")

        # If song count is below 30
        if len(songs) < spl:
            songs_sample = random.sample(songs, len(songs))
            if len(songs) > 2:
                filler_tracks = random.sample(related_artist_top_songs1['tracks'],3) # Grab 3 filler tracks from related artist 1
                for j in range(len(filler_tracks)):
                    if filler_tracks[j]['explicit'] == False: # Check if songs are explicit
                        songs_sample.append(filler_tracks[j]['uri'])
                        print(f"Track '{filler_tracks[j]['name']}' by {filler_tracks[j]['artists'][0]['name']} added to sample pool.")
                    else:
                        print(f"Track '{filler_tracks[j]['name']}' by {filler_tracks[j]['artists'][0]['name']} removed for explicit rating.")
                        
        # If song count is 30 or greater, take a random sample of 30 songs and add to playlist         
        else: 
            songs_sample = random.sample(songs,spl)
        all_songs.extend(songs_sample)
    # Add playlists to spotify
    add_songs_to_playlist(all_songs, user_uri)

# Create playlist
@app.route('/create', methods=['GET'])
@jwt_required()
def create_playlist():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    username = user.username
    if user.playlist_uri:
        user_uri = user.playlist_uri
        playlist_url = user.playlist_url
    else:
        try:
            playlist = sp.user_playlist_create(user=me, name=f"{username}'s Playlist", public=False, collaborative=False, description='')
            playlist_id = playlist['id']
            sp.playlist_change_details(playlist_id, collaborative=True)
            user_uri = playlist['uri']
            playlist_url = playlist['external_urls']['spotify']
            user.playlist_uri = user_uri
            user.playlist_url = playlist_url
            db.session.commit()
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    items = Item.query.filter_by(user_id=user_id, selected=True).all()
    if items:
        try:
            playlist_creation(items, user)
            return jsonify(playlist_url)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'No items found for this user'}), 404

if __name__ == '__main__':
    app.run(debug=True)
