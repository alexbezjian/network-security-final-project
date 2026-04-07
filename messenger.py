#!/usr/bin/env python
# coding: utf-8

# In[1]:

"""
secure_messenger.py

Single-file secure messaging system.

Modes:
    python secure_messenger.py server
    python secure_messenger.py client

Features
--------
• Authentication server
• Online user list
• Peer discovery
• Diffie-Hellman key exchange (X25519)
• AES-GCM encrypted messages
• Console commands:
      list
      send USER MESSAGE
      exit
"""

import socket
import threading
import json
import sys
import os

from argon2 import PasswordHasher

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# CRYPTO UTILITIES
def generate_keypair():
    """Generate ephemeral Diffie-Hellman key pair."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key

def compute_shared(private_key, peer_public_bytes):
    """Compute Diffie-Hellman shared secret."""
    peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public)

def derive_key(shared_secret):
    """Derive AES key from shared secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-messenger",
    )

    return hkdf.derive(shared_secret)

def encrypt(key, message):
    """Encrypt message with AES-GCM."""
    aes = AESGCM(key)

    nonce = os.urandom(12)

    ciphertext = aes.encrypt(nonce, message.encode(), None)

    return nonce + ciphertext

def decrypt(key, data):
    """Decrypt AES-GCM message."""
    nonce = data[:12]
    ciphertext = data[12:]

    aes = AESGCM(key)

    plaintext = aes.decrypt(nonce, ciphertext, None)

    return plaintext.decode()

# SERVER IMPLEMENTATION

HOST = "0.0.0.0"
PORT = 9000

ph = PasswordHasher()

# user database
user_db = {
    "alice": ph.hash("alice123"),
    "bob": ph.hash("bob123"),
    "albert": ph.hash("albert123"),
}

online_users = {}

def handle_client(conn, addr):
    """Handle connected client."""
    username = None

    while True:

        try:
            data = conn.recv(4096)
            if not data:
                break
            message = json.loads(data.decode())
            command = message["command"]
            # LOGIN
            if command == "login":
                username = message["username"]
                password = message["password"]
                port = message["port"]
                if username not in user_db:
                    conn.send(b"FAIL")
                    continue
                try:
                    ph.verify(user_db[username], password)
                    online_users[username] = (addr[0], port)
                    conn.send(b"OK")
                    print(f"{username} logged in from {addr[0]}")
                except:
                    conn.send(b"FAIL")

            # LIST USERS
            elif command == "list":
                conn.send(json.dumps(online_users).encode())

            # LOGOUT
            elif command == "logout":
                if username in online_users:
                    del online_users[username]
                break
        except:
            break
    conn.close()
def run_server():
    """Start authentication server."""

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print("Server running on port 9000")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

# PEER LISTENER

class PeerListener(threading.Thread):
    """
    Client listener that accepts incoming peer messages.
    """
    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port

    def run(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("0.0.0.0", self.port))
        listener.listen()
        print(f"Listening for peers on port {self.port}")

        while True:
            conn, addr = listener.accept()
            threading.Thread(
                target=self.handle_peer,
                args=(conn,),
                daemon=True
            ).start()
    def handle_peer(self, conn):
        """Handle incoming peer connection."""
        private, public = generate_keypair()

        # receive peer public key
        peer_key = conn.recv(32)

        # send own public key
        conn.send(public.public_bytes_raw())
        shared = compute_shared(private, peer_key)
        key = derive_key(shared)
        data = conn.recv(4096)
        message = decrypt(key, data)
        print("\nNew message:", message)

# CLIENT IMPLEMENTATION

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000

class Client:

    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((SERVER_HOST, SERVER_PORT))
        self.username = None
        self.port = None

    # LOGIN
    def login(self):
        self.username = input("Username: ")
        password = input("Password: ")
        self.port = int(input("Listening port: "))
        msg = {
            "command": "login",
            "username": self.username,
            "password": password,
            "port": self.port,
        }
        self.server.send(json.dumps(msg).encode())
        response = self.server.recv(1024)

        if response == b"OK":
            print("Login successful")
            listener = PeerListener(self.port)
            listener.start()
        else:
            print("Login failed")
            sys.exit()

    # LIST USERS

    def list_users(self):
        self.server.send(json.dumps({"command": "list"}).encode())
        data = self.server.recv(4096)
        users = json.loads(data.decode())
        print("Online users:")

        for user, info in users.items():
            print(user, info)

    # SEND MESSAGE

    def send_message(self, user, message):
        self.server.send(json.dumps({"command": "list"}).encode())
        users = json.loads(self.server.recv(4096).decode())

        if user not in users:
            print("User not online")
            return
        ip, port = users[user]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.connect((ip, port))

        private, public = generate_keypair()

        # send public key
        sock.send(public.public_bytes_raw())

        peer_key = sock.recv(32)

        shared = compute_shared(private, peer_key)

        key = derive_key(shared)

        encrypted = encrypt(key, f"{self.username}: {message}")

        sock.send(encrypted)

        sock.close()

    # COMMAND LOOP

    def run(self):
        while True:
            command = input("> ")
            if command == "list":
                self.list_users()
            elif command.startswith("send"):
                parts = command.split(" ", 2)
                if len(parts) < 3:
                    print("Usage: send USER MESSAGE")
                    continue
                user = parts[1]
                message = parts[2]
                self.send_message(user, message)
            elif command == "exit":
                self.server.send(json.dumps({"command": "logout"}).encode())
                break

# MAIN

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python secure_messenger.py server")
        print("  python secure_messenger.py client")
        sys.exit()

    mode = sys.argv[1]

    if mode == "server":
        run_server()

    elif mode == "client":
        client = Client()
        client.login()
        client.run()
# In[ ]:
