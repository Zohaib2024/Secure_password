import json
import os

def load_json(file_name, default={}):
    if os.path.exists(file_name):
        with open(file_name, "r") as f:
            return json.load(f)
    return default

def save_json(file_name, data):
    with open(file_name, "w") as f:
        json.dump(data, f, indent=4)
