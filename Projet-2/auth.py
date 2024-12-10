import json
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def add_user(username, password, filename="users.json"):
    # Hash le mot de passe
    hashed_password = hash_password(password)
    
    # Charge les utilisateurs existants
    try:
        with open(filename, "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}

    # Ajoute le nouvel utilisateur
    users[username] = {"password": hashed_password}

    # Sauvegarde les utilisateurs dans le fichier
    with open(filename, "w") as f:
        json.dump(users, f)

def verify_user(username, password, filename="users.json"):
    # Charge les utilisateurs existants
    try:
        with open(filename, "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        return False
    
    # Vérifie si l'utilisateur existe
    if username in users:
        hashed_password = users[username]["password"]
        # Compare le mot de passe avec le mot de passe haché
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            return True
    return False
