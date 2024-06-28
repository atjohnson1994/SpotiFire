import os
import json
from spotipy.cache_handler import CacheHandler

class CustomCacheHandler(CacheHandler):
    def __init__(self, cache_path=None):
        self.cache_path = cache_path or ".spotify_cache"
        
    def get_cached_token(self):
        if os.path.exists(self.cache_path):
            with open(self.cache_path, 'r') as file:
                return json.load(file)
        return None

    def save_token_to_cache(self, token_info):
        with open(self.cache_path, 'w') as file:
            json.dump(token_info, file)

    def delete_cached_token(self):
        if os.path.exists(self.cache_path):
            os.remove(self.cache_path)
