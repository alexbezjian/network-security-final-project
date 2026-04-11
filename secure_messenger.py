#!/usr/bin/env python3

"""
* file includes both server and client implementation 
* which one runs depends on the command line arg: 
    - python3 secure_messenger.py server 
    - python3 secure_messenger.py client 
* the server handles the login, peer discovery (LIST), and logout
* the client handles the login, sending and receiving P2P messages
* after login, all messages go directly client to client, where the server
  is never on the message path

* crypto primitives used: 
    - Argon2id: password hashing on the server includes memory hard and brute force
      resistance
    - X25519: ephemeral DH key exchange (client to server and peer to peer)
    - Ed25519: server signs session certs binding username to ephemeral key
    - AES-256-GCM: authenticated encryption for all channels
    - HKDF-SHA256: key derivation from raw DH output 
    - nonces: prevents replay attacks at login and logout 
    - session token: 32 byte random secret required for LIST and LOGOUT
    - message counter: incrementing integer prevents P2P message replay

Architecture:
  - Authentication Server: discovery, login CA, session management
  - Client: P2P messaging after discovery

Usage:
  - python secure_messenger.py server
  - python secure_messenger.py client [server_host]   (default 127.0.0.1)
"""

import os # to generate cryptographically secure random bytes
import sys # sys.argv to read command line args & sys.exit to stop program
import json # encodes/decodes msgs as JSOn so they can travel over sockets
import socket # TCP networking: connects clients to server and peers to peers
import threading # lets server handle multiple clients at the same time
import time # time.time gives current unix timestamp used in session certs
import struct # struct.pack/unpack converts ints to/from raw bytes for framing
import hmac # HMAC-SHA256 for signing the logout msg
import hashlib # provides SHA256 used with hmac
import secrets # secrets.token_hex() generates cryptographically secure random tokens


# ADDITIONAL IMPORTS (pip install cryptography argon2-cffi)
from argon2 import PasswordHasher # password hashing library 
from argon2.exceptions import VerifyMismatchError # throws when pwd is wrong

# Ed25519: server's long term signing key used to sign session certs
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

# X25519: ephemeral DH used for key exchange & is never stored
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)

# HKDF: key derivation func: turns raw DH into proper AES key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# hashes and serialization: config HKDF and export public keys as bytes
from cryptography.hazmat.primitives import hashes, serialization

# AES-256-GCM: authenticates encryption: CIA
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# throws when AES-GCM detects a tampered or corrupted msg 
from cryptography.exceptions import InvalidSignature


# CONSTANTS
SERVER_PORT = 9000 # port the auth server listens on 
RECV_BUF = 65536 # max bytes to read in recv() call 
SESSION_TIMEOUT = 3600 # session certs seconds expire after 1 hr aka 3600 secs


# TCP FRAMING: length-prefixed messages over TCP
# to avoid the issue of messages arriving merged or arriving split across 
# multiple recv() calls, we prepend every msg with a 4 byte int saying 
# how many bytes will follow. so the receiver reads 4 bytes first, knows 
# the length, then reads exactly that many bytes guaranteeing msg boundaries

# prepends a 4 byte big endian length header & sends full msg
def send_msg(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)

# reads the 4 byte length header then reads exactly that many bytes
def recv_msg(sock: socket.socket) -> bytes:
    raw_len = _recvall(sock, 4) # reads 4 byte length prefix
    if not raw_len:
        raise ConnectionError("Connection closed")
    length = struct.unpack(">I", raw_len)[0] # decodes int
    return _recvall(sock, length) # reads exactly "length"  bytes

# keeps reading until exactly n bytes
# needed bc a single recv() may return fewer bytes than requested
def _recvall(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data)) # asks for however many bytes are missing
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        data.extend(chunk)
    return bytes(data)

# converts py dictionary to JSON bytes and sends as frames msg
def send_json(sock: socket.socket, obj: dict) -> None:
    send_msg(sock, json.dumps(obj).encode())

# receives a framed msg and deserializes it from JSON to a dict
def recv_json(sock: socket.socket) -> dict:
    return json.loads(recv_msg(sock).decode())


# CRYPTO UTILITIES

# generates a fresh ephermeral X25519 Diffie-Hellman keypair
# called once per login & private key is never saved to disk
# achieves PFS bc even if long-term secrets are later compromised, past session
# are safe bc these ephemeral keys no longer exist 
def gen_x25519():
    priv = X25519PrivateKey.generate() # generates cryptographically random private key 
    pub  = priv.public_key() # derives corresponding pub key
    return priv, pub

# exports X25519 pub key as raw 32 bytes so it can be sent over network 
def x25519_pub_bytes(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

# reconstructs X25519 pub key obj from raw bytes received over the network
def x25519_pub_from_bytes(b: bytes):
    return X25519PublicKey.from_public_bytes(b)

# performs x25519 DH: both sides compute own priv key * other's pub key,
# they arrive at same shared secret w/o ever transmitting it
# (eavesdropper who sees only the 2 pub keys can't commute this secret)
def dh_exchange(priv, peer_pub_bytes: bytes) -> bytes:
    peer_pub = x25519_pub_from_bytes(peer_pub_bytes) # reconstructs peer's pub key obj
    return priv.exchange(peer_pub) # computes shared secret 

# derives a cryptographic key from raw DH output using HKDF-SHA256
# info param separates keys so same DH exchange produces diff keys for diff purposes:
    # info=b'client-server-session' -> K_cs (client to server channel)
    # info-b'peer-messaging' -> K_AB (peer to peer channel)
def hkdf_derive(shared: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), # uses SHA-256 as underlying hash func
        length=length, # output 32 bytes = 256 bit AES key 
        salt=None, # no salt needed bc DH output is already random
        info=info, # doman separation label 
    ).derive(shared)

# encrypt plaintext using AES-256-GCM authenticated encryption 
# AES-GCM gives the 3 guarantees: CIA 
def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12) # fresh 12 byte nonce generated per msg so identical plaintexts always produce diff ciphertexts
    ct = AESGCM(key).encrypt(nonce, plaintext, aad or None) # encrypt and authenticate
    return nonce + ct # returns 12 byte nonce concatenated (prepended) w ciphertext+tag

# decrypts AES-256-GCM msg, throws error if auth fails, meaning any tampering is 
# detected before ever seeing plaintext 
def aes_decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    nonce, ct = data[:12], data[12:] # split off 12 byte nonce 
    return AESGCM(key).decrypt(nonce, ct, aad or None) # decrypt and verify integrity

# signs msg w server's ed25519 private key (SK_S) 
# used by server to sign session certs aka lighweight CA
def ed25519_sign(priv: Ed25519PrivateKey, msg: bytes) -> bytes:
    return priv.sign(msg)

# verifies ed25519 signature using server's pub key (PK_S)
# returs true if valid and false if signature is wrong or msg was tampered
def ed25519_verify(pub: Ed25519PublicKey, sig: bytes, msg: bytes) -> bool:
    try:
        pub.verify(sig, msg) # throws InvalidSignature if verification fails
        return True
    except InvalidSignature:
        return False

# exports ed25519 pub key as raw 32 bytes to transmit over network
def encode_pub_ed(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

# reconstructs ed25519 pub key obj from raw bytes 
def decode_pub_ed(b: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b)


# SESSION CERTS: server's CA functionality 
# session cert binds username to ephemeral DH pub key, signed by server with SK_S
# allowing peers to authenticate each other w/o contacting the server again

# cert = Ed25519_sign(SK_S, username | eph_pub | timestamp)
# ex: when alice wants to msg bob, she gets bob's cert from server, verifies the
# ed25519 signature with PK_S, and knows server vouched that this DH pub key belongs to 
# Bob, which achieves mutual authentication 

# creates signed session cert binding user to their ephemeral DH key
def make_cert(sk: Ed25519PrivateKey, username: str, eph_pub: bytes) -> bytes:
    ts = int(time.time()).to_bytes(8, "big") # current timestamp as 8 bytes
    payload = username.encode() + b"|" + eph_pub + b"|" + ts # builds payload to sign
    sig = ed25519_sign(sk, payload) # signs with SK_S
    return json.dumps({ # returns as JSON bytes so easy to transmit and parse later
        "username": username,
        "eph_pub": eph_pub.hex(), # DH pub key in hex
        "timestamp": int.from_bytes(ts, "big"), # timestamp as int
        "sig": sig.hex(), # ed25519 signature in hex
    }).encode()

# verifies a session cert with PK_S and returns the cert as a dict of valid and not expired
# or none if invalid. this is called by both sides during peer auth 
def verify_cert(pk: Ed25519PublicKey, cert_bytes: bytes) -> dict | None:
    try:
        c = json.loads(cert_bytes.decode()) # parse JSON cert
        ts = c["timestamp"].to_bytes(8, "big") # reconstructs timestamp bytes
        eph_pub = bytes.fromhex(c["eph_pub"]) # reconstructs DH key bytes
        payload = c["username"].encode() + b"|" + eph_pub + b"|" + ts # rebuilds signed payload
        sig = bytes.fromhex(c["sig"]) # reconstructs signature bytes 
        if not ed25519_verify(pk, sig, payload): # checks signature against PK_S
            return None # bad signature gets rejected 
        # check freshness, checks cert is not expired 
        if time.time() - c["timestamp"] > SESSION_TIMEOUT:
            return None # expired means rejected 
        return c # cert is valid 
    except Exception:
        return None # any parsing error -> reject 

# SERVER
# pre-configured users: pwds never stored in plaintext, each is hashed with Argon2id
# making brute force attacks expensive even if this data leaks 
_ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
# time_cost=2: runs hash function 2 times 
# memory_cost=65536: uses 64 MB of RAM per hash 
# parallelism=2: uses 2 parallel threads 

# hashes all 3 pwds at start
# hashes are what server checks against during login 
USER_DB: dict[str, str] = {
    "alice": _ph.hash("alice123"), # stored as Argon2id hash, never plaintext
    "bob": _ph.hash("bob123"),
    "jill": _ph.hash("jill123"),
}

# SERVER STATE: tracks online users and valid session tokens at runtim

# holds all runtime state for server: ed25519 keys, online user, session tokens
class ServerState:
    # generates server's long term ed25519 signing keypair at startup
    # SK_S signs session certs, PK_S sent to clients at login so they can verify peer certs w/o contacting server again
    def __init__(self):
        self.sk: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        self.pk: Ed25519PublicKey = self.sk.public_key()
        self.pk_bytes: bytes = encode_pub_ed(self.pk) # PK_S as raw bytes

        # threading.Lock ensure only 1 thread modifies shared data at a time otherwise 2 simultaneous logins could corrupt online list
        self._lock = threading.Lock()
        self._online: dict[str, dict] = {} # maps username to connection info + cert + ephemeral pub key
        self._tokens: dict[str, str]  = {} # maps session token to user used to auth LIST and LOGOUT

    # adds newly logged in user to online list and token registry 
    def register(self, username: str, ip: str, port: int, cert_bytes: bytes, token: str, eph_pub: bytes):
        with self._lock: # gets lock before modifying shared state
            self._online[username] = {
                "ip": ip, "port": port, # peer's IP address
                "cert": cert_bytes.hex(), # peer's P2P listening port
                "eph_pub": eph_pub.hex(), # ephemeral DH pub key in hex
            }
            self._tokens[token] = username # registers session token

    # checks if token is valid, returns user it belongs to or none 
    def verify_token(self, token: str) -> str | None:
        with self._lock:
            return self._tokens.get(token) # returns none if token doesn't exist

    # returns a snapshot of online user list to avoid race conditions 
    def get_online(self) -> dict:
        with self._lock:
            return dict(self._online) # returns a copy 

    # invalidates a session token and removes user from online list 
    def logout(self, token: str):
        with self._lock:
            username = self._tokens.pop(token, None) # removes token, gets user
            if username:
                self._online.pop(username, None) # removes from online list 

STATE: ServerState | None = None # global server state obj, init when run_server() starts 


# PER CLIENT HANDLER:  runs in its own thread for each connected client 

# handles one client connection from login through logout 
# Login protocol: to prevent offline dictionary attacks 
    # step 1: client sends HELLO with ephemeral Dh pub key + nonce Nc
    # step 2: server replies w its ephemeral DH pub key + nonce Ns
    # step 3: both sides derive shared session key K_cs via HKDF over DH output
    # step 4: client sends password + both nonces encrypted under K_cs, password never sends in plaintext,
    # attacker can't test guesses offline bc they would need the server's ephemeral priv key
    # step 5: server verifies argon2id hash, issues signed cert, returns cert + token
# after login, LIST and LOGOUT commands are encrypted under K_cs and require session token 
def handle_client(conn: socket.socket, addr):
    session_key: bytes | None = None # K_cs: established after DH handshake 
    token: str | None = None # session token: set after successful login

    try:
        #  step 1: receive HELLO from client 
        hello = recv_json(conn)
        if hello.get("cmd") != "hello":
            return # not a valid hello msg, drops this connection 

        username = hello["username"] # client's claimed user
        nc = bytes.fromhex(hello["nc"]) # client nonce Nc
        c_eph_pub_b = bytes.fromhex(hello["c_eph_pub"]) # client's ephemeral Dh pub key

        # step 2: generates server ephemeral DH keypair and nonce Ns
        s_priv, s_pub = gen_x25519() # fresh ephemeral keypair for this session
        s_eph_pub_b = x25519_pub_bytes(s_pub) # exports pub key as bytes 
        ns = os.urandom(16) # Ns: 16 random bytes

        # sends server's ephemeral pub key and Ns to client 
        send_json(conn, {"s_eph_pub": s_eph_pub_b.hex(), "ns": ns.hex()})

        # setp 3: both sides service K_cs from DH exchange 
            # server computes shared secret
            # client computed same shared secret 
        shared = dh_exchange(s_priv, c_eph_pub_b)
        session_key = hkdf_derive(shared, b"client-server-session") # HKDF turns raw DH output to 256 but AES key 

        # step 4: receives and decrypts encrypted login payload 
        raw = recv_msg(conn) # receives raw encrypted bytes 
        payload_bytes = aes_decrypt(session_key, raw) # decrypts with K_cs 
        payload = json.loads(payload_bytes.decode()) # parses JSON payload 

        # verifies nonces to prevent replay attacks on login exchange 
        if bytes.fromhex(payload["nc"]) != nc: # proves client's msg is fresh 
            send_msg(conn, aes_encrypt(session_key, json.dumps({"error": "bad nonce"}).encode()))
            return
        if bytes.fromhex(payload["ns"]) != ns: # proves client received and is responding
            send_msg(conn, aes_encrypt(session_key, json.dumps({"error": "bad nonce"}).encode()))
            return

        # gets login fields from decrypted payload 
        password = payload["password"]
        client_eph_pub  = bytes.fromhex(payload["c_eph_pub"]) # client's DH key for cert 
        port = int(payload["port"]) # client's P2P listening port

        # checks user exists before trying to verifty pwd
        if username not in USER_DB:
            send_msg(conn, aes_encrypt(session_key, json.dumps({"error": "bad credentials"}).encode()))
            return
        # verifies enteres pwd against stored hash, argon rehashes pwd w stored salt and compares
        try:
            _ph.verify(USER_DB[username], password)
        except VerifyMismatchError: # if wrong pwd, throws encrypted error so attacker doesn't learn any info
            send_msg(conn, aes_encrypt(session_key, json.dumps({"error": "bad credentials"}).encode()))
            return

        # step 5: gives session certs & registers user as online
        cert_bytes = make_cert(STATE.sk, username, client_eph_pub) # cert binds this user to their ephemeral DH pub key signed with SK_S, peers verify this cert to auth each other
        token = secrets.token_hex(32) # generates cryptographically random hex session token that is secret and required for all future LIST and LOGOUT
        STATE.register(username, addr[0], port, cert_bytes, token, client_eph_pub) # registers user and adds to online list and token registry 

        # sends session token, cert, and PK_S back to client encrypted under K_cs
        resp = json.dumps({
            "status": "ok",
            "token": token, # secret token 
            "cert": cert_bytes.hex(), # clients own session cert 
            "ns": ns.hex(),
            "pk_s": STATE.pk_bytes.hex(),  # server's Ed25519 pub key
        }).encode()
        send_msg(conn, aes_encrypt(session_key, resp)) # send encrypted under K_cs
        print(f"[server] {username} logged in from {addr[0]}:{port}")

        #  COMMAND LOOP: handles LIST and LOGOUT after successful login
        while True:
            raw = recv_msg(conn)
            msg = json.loads(aes_decrypt(session_key, raw).decode())
            cmd = msg.get("cmd")

            # verifies session token before returning user list
            if cmd == "list":
                if STATE.verify_token(msg.get("token", "")) is None:
                    send_msg(conn, aes_encrypt(session_key, json.dumps({"error": "unauthorized"}).encode()))
                    continue
                online = STATE.get_online()  # returns online list encrypted under K_cs
                send_msg(conn, aes_encrypt(session_key, json.dumps({"users": online}).encode()))

            elif cmd == "logout":
                if STATE.verify_token(msg.get("token", "")) is not None:
                # verifies HMAC-SHA256 logout signature
                    try:
                        nc_logout = bytes.fromhex(msg["nc"])
                        payload_str = f"logout|{username}|{msg['nc']}" # rebuilds payload
                        expected_mac = hmac.new(
                            session_key, #K_cs as HMAC ket 
                            payload_str.encode(),
                            hashlib.sha256,
                        ).digest()
                        received_mac = bytes.fromhex(msg["mac"]) # MAC from client 
                        # compare_digest to prevent timing attacks 
                        if not hmac.compare_digest(expected_mac, received_mac):
                            send_msg(conn, aes_encrypt(session_key, json.dumps({"error": "bad logout signature"}).encode()))
                            continue # rejects logout attempt 
                    except Exception:
                        send_msg(conn, aes_encrypt(session_key, json.dumps({"error": "malformed logout"}).encode()))
                        continue
                    # signature verifies, invalidate token and remove from online list 
                    STATE.logout(msg["token"])
                    token = None # clears
                # confirms logout to client 
                send_msg(conn, aes_encrypt(session_key, json.dumps({"status": "ok"}).encode()))
                print(f"[server] {username} logged out")
                break # exit command loop and ends thread 

            else:
                send_msg(conn, aes_encrypt(session_key, json.dumps({"error": "unknown cmd"}).encode()))

    except Exception as e:
        pass # connection fropped or client crashed so clean up 
    finally: # clean up: if client disconnected without logging out, removes them from list
        if token:
            STATE.logout(token)
        conn.close()

# starts auth server, each client connection gets its own thread 
def run_server():
    global STATE
    STATE = ServerState() # init server state and generate ed25519 keypair 
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create TCP socket
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # allows reuse 
    srv.bind(("0.0.0.0", SERVER_PORT)) # listens on all net interfaces, port 9000
    srv.listen() # starts accepting connections 
    print(f"[server] Listening on port {SERVER_PORT}")
    while True:
        conn, addr = srv.accept() 
        # new thread per client so multiple clients can be served at same time 
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


#  PEER LISTENER: background thread inside each client for incoming P2P msgs 
class PeerListener(threading.Thread):
    # listens for incoming peer connects on specified port 
    # when peer connects, runs mutual auth and key protocol then loops receiving encrypted msgs 
    def __init__(self, port: int, username: str,
                 cert_bytes: bytes, eph_priv, eph_pub_b: bytes,
                 pk_s: Ed25519PublicKey):
        super().__init__(daemon=True) # daemon thread exits when main program exits
        self.port = port # port listener binds to 
        self.username = username # own username 
        self.cert_bytes = cert_bytes # session cert 
        self.eph_priv = eph_priv # ephemeral DH priv key 
        self.eph_pub_b = eph_pub_b # ephemeral Dh pub key shared w peers 
        self.pk_s = pk_s # and server's ed25519 pub key to verify peer certs 
        # tracks last seen msg counter per sender to detect replayed msgs 
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock() # protects from concurrent thread 

    # binds to P2P listening port and accepts incoming peer connections 
    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port)) # bind
        srv.listen()
        print(f"[peer] Listening for peers on port {self.port}")
        while True:
            conn, addr = srv.accept() # waits for peer to connect
            # each incoming peer connection gets own handler thread 
            threading.Thread(target=self._handle_peer, args=(conn, addr), daemon=True).start()

    # run mutual auth and key protocol for one incoming peer connections 
    def _handle_peer(self, conn: socket.socket, addr):
        try:
            # step 1: receive initiator's cert + eph_pub
            peer_cert_b = recv_msg(conn) 
            peer_pub_b = recv_msg(conn)

            # step 2: verifies initiator's cert
            c = verify_cert(self.pk_s, peer_cert_b)
            if c is None:
                conn.close(); return # invalid or expired cert so rejected
            # checks Dh pub key in cert matches what was sent
            if bytes.fromhex(c["eph_pub"]) != peer_pub_b:
                conn.close(); return # key mismatch then rejected 
            peer_username = c["username"] # now know who this peer is 

            # step 3: computes K_AB, shared peer to peer session key 
            # DH exchange where our priv key and their pub key = shared secret 
            shared = dh_exchange(self.eph_priv, peer_pub_b)
            k_ab = hkdf_derive(shared, b"peer-messaging")

            # send own cert + eph_pub + AES{Nb}
            nb = os.urandom(16)
            send_msg(conn, self.cert_bytes)
            send_msg(conn, self.eph_pub_b)
            send_msg(conn, aes_encrypt(k_ab, nb))

            # step 4: receive and verify Nb+1 from initiator 
            raw = recv_msg(conn)
            nb1_dec = aes_decrypt(k_ab, raw)
            expected = (int.from_bytes(nb, "big") + 1).to_bytes(16, "big")
            if nb1_dec != expected:
                conn.close(); return # wrong answer so reject 
            
            # mutual auth completed so both sides have verified each other's server signed certs and both have proven they came from same K_AB

            # MESSAGE RECEIVE LOOP
            with self._lock:
                self._counters.setdefault(peer_username, -1) # init counter tracking 

            while True:
                raw = recv_msg(conn) # receive next encrypted msg frame 
                if not raw:
                    break
                msg_json = json.loads(aes_decrypt(k_ab, raw).decode()) 
                counter = msg_json["counter"] # sequence num for replay protection 
                sender = msg_json["sender"] # sender's username 
                text = msg_json["text"] # actual msg text 

                # replay protection: rejects any msg w a counter not greater than last seen 
                with self._lock:
                    last = self._counters.get(sender, -1)
                    if counter <= last:
                        continue # reject replay
                    self._counters[sender] = counter # update last seen counter

                print(f"\n[{sender}]: {text}\n> ", end="", flush=True) # displays msg to user 

        except Exception:
            pass # peer disconnected or error so clean up 
        finally:
            conn.close()


# CLIENT
class Client:

    # authenticates with server, then communicates directly with other clients peer to peer, but never relays msgs
    def __init__(self, server_host: str):
        self.server_host = server_host # server IP address
        self.server_conn: socket.socket | None = None # TCP connection to server 
        self.session_key: bytes | None = None # K_cs: shared w server 
        self.token: str | None = None # secret session token 
        self.username: str | None = None # username 
        self.cert_bytes: bytes | None = None # session cert 
        self.eph_priv = None # ephemeral Dh priv key
        self.eph_pub_b: bytes | None = None # ephemeral DH pub key bytes
        self.pk_s: Ed25519PublicKey | None = None # server's ed25519 pub key 
        self.peer_listener: PeerListener | None = None # background listener thread 
        # per peer send counter
        self._send_counters: dict[str, int] = {}

    # LOGIN
    # runs full login protocol: DH handshale, encrypted password, receive cert 
    def login(self):
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        port = int(input("Listening port (e.g. 9001): ").strip())

        # generates fresh ephemeral X25519 keypair for this session
        self.eph_priv, eph_pub = gen_x25519()
        self.eph_pub_b = x25519_pub_bytes(eph_pub) # export as bytes for sending

        # connects to server, opens TCP connection to auth server 
        self.server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_conn.connect((self.server_host, SERVER_PORT))

        # HELLO: sends ephemeral pub key and client nonce NC
        nc = os.urandom(16)
        send_json(self.server_conn, {
            "cmd": "hello",
            "username": username,
            "nc": nc.hex(),
            "c_eph_pub": self.eph_pub_b.hex(),
        })

        # receives server eph pub + ns 
        resp = recv_json(self.server_conn)
        s_eph_b = bytes.fromhex(resp["s_eph_pub"])
        ns = bytes.fromhex(resp["ns"])

        # derive K_cs: client server session key 
        shared = dh_exchange(self.eph_priv, s_eph_b)
        self.session_key = hkdf_derive(shared, b"client-server-session")

        # sends encrypted login payload where password sends inside AES-GCM
        payload = json.dumps({
            "password": password, 
            "nc": nc.hex(),
            "ns": ns.hex(),
            "c_eph_pub": self.eph_pub_b.hex(),
            "port": port,
        }).encode()
        send_msg(self.server_conn, aes_encrypt(self.session_key, payload))

        # receives server's login response 
        raw = recv_msg(self.server_conn)
        data = json.loads(aes_decrypt(self.session_key, raw).decode())

        if "error" in data:
            print(f"Login failed: {data['error']}")
            sys.exit(1)

        # stores everything needed for rest of session 
        self.token = data["token"]
        self.cert_bytes = bytes.fromhex(data["cert"])
        self.pk_s = decode_pub_ed(bytes.fromhex(data["pk_s"]))
        self.username = username

        print(f"Logged in as {username}. Type 'help' for commands.")

        # starts peer listener in background thread, waits for other clients to connect and send msgs
        self.peer_listener = PeerListener(
            port, username, self.cert_bytes,
            self.eph_priv, self.eph_pub_b, self.pk_s,
        )
        self.peer_listener.start()

    # LIST
    # requests the list of online users from server
    # requires a valid session token. unauth users cant call this 
    def list_users(self):
        # sends LIST command w session token and encrypted under K_cs
        msg = json.dumps({"cmd": "list", "token": self.token}).encode()
        send_msg(self.server_conn, aes_encrypt(self.session_key, msg))
        # receives and decrypts server's response 
        raw  = recv_msg(self.server_conn)
        data = json.loads(aes_decrypt(self.session_key, raw).decode())
        if "error" in data:
            print(f"Error: {data['error']}")
            return
        users = data.get("users", {})
        if not users:
            print("No users online.")
            return
        print("Online users:")
        for uname, info in users.items():
            marker = " (you)" if uname == self.username else ""
            print(f"  {uname}  {info['ip']}:{info['port']}{marker}")

    #  SEND MESSAGE: peer to peer, server is not involved in delivering 
    # sends end to end encrypted msg directly to another client
    # server never sees msg content, only the sender and recipient can decrypt it 
    def send_message(self, target: str, text: str):
        if target == self.username:
            print("Cannot message yourself.")
            return

        # step 1: fetch target's connection info and cert from the server 
        msg = json.dumps({"cmd": "list", "token": self.token}).encode()
        send_msg(self.server_conn, aes_encrypt(self.session_key, msg))
        raw = recv_msg(self.server_conn)
        data = json.loads(aes_decrypt(self.session_key, raw).decode())

        users = data.get("users", {})
        if target not in users:
            print(f"{target} is not online.")
            return

        info = users[target]
        peer_ip  = info["ip"]
        peer_port = int(info["port"])
        peer_cert_b = bytes.fromhex(info["cert"])
        peer_pub_b = bytes.fromhex(info["eph_pub"])

        # step 2: verifies target's cert before making connection 
        # first part of mutual auth: verify server signed this cert for the target user, if signature fails, we do not make connection 
        c = verify_cert(self.pk_s, peer_cert_b)
        if c is None or c["username"] != target:
            print("Peer certificate invalid. Aborting.")
            return
        if bytes.fromhex(c["eph_pub"]) != peer_pub_b: # also verify DH pub key in cert matches what server reports 
            print("Peer public key mismatch. Aborting.")
            return

        # step 3: open a direct TCP connection to the target's peer to peer port 
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10) # 10 sec connection timeout 
            sock.connect((peer_ip, peer_port)) # direct TCP to peer w/o server relay 
        except Exception as e:
            print(f"Could not connect to {target}: {e}")
            return

        try:
            # step 4: sends cert + eph_pub to peer 
            send_msg(sock, self.cert_bytes)
            send_msg(sock, self.eph_pub_b)

            # receives peer's cert + eph_pub + AES{Nb}
            their_cert_b = recv_msg(sock) # peer's session cert 
            their_pub_b  = recv_msg(sock) # peer's ephemeral DH public key 
            nb_enc       = recv_msg(sock) # AES_KAB{Nb} 

            # verifies peer's cert aka second half od mutual auth 
            tc = verify_cert(self.pk_s, their_cert_b)
            if tc is None or tc["username"] != target:
                print("Peer authentication failed.")
                return
            if bytes.fromhex(tc["eph_pub"]) != their_pub_b:
                print("Peer key mismatch.")
                return

            # computes K_AB and completes challenge response 
            shared = dh_exchange(self.eph_priv, their_pub_b)
            k_ab = hkdf_derive(shared, b"peer-messaging")

            # decrypts challenge nonce Nb sent by peer 
            nb = aes_decrypt(k_ab, nb_enc)

            # sends Nb+1 encrypted to prove derived same K_AB
            nb1 = (int.from_bytes(nb, "big") + 1).to_bytes(16, "big")
            send_msg(sock, aes_encrypt(k_ab, nb1))

            # step 5: sends encrypted message with counter 
            # counter increments w every msg to this reipient, receiver rejects any counter less than or equal to last seen so replayed captured msg will always be rejected 
            counter = self._send_counters.get(target, 0) + 1
            self._send_counters[target] = counter # saves updated counter 

            app_msg = json.dumps({
                "counter": counter,
                "sender": self.username,
                "text": text,
            }).encode()
            send_msg(sock, aes_encrypt(k_ab, app_msg))

        except Exception as e:
            print(f"Error sending message: {e}")
        finally:
            sock.close() # closes p2p socket after each msg 

    # LOGOUT
    # sends a signed logout request to server, then discards all session materials 
    def logout(self):
        if self.server_conn and self.token:
            try:
                # fresh nonce prevents replay of a captured logout msg
                nc_logout = os.urandom(16).hex()
                payload_str = f"logout|{self.username}|{nc_logout}" # payload = logout | username | nonce 
                # HMAC-SHA256 keyed w K_cs proves this logout is legitimate 
                mac = hmac.new(
                    self.session_key, # K_cs as HMAC key 
                    payload_str.encode(),
                    hashlib.sha256,
                ).digest().hex()

                msg = json.dumps({
                    "cmd": "logout",
                    "token": self.token, # session token identifies who is logging out 
                    "nc": nc_logout, 
                    "mac": mac, 
                }).encode()
                # sends signed logout request, encrypted under K_cs 
                send_msg(self.server_conn, aes_encrypt(self.session_key, msg))
                recv_msg(self.server_conn) # wait for OK
            except Exception:
                pass # if connection already dropped, still continue to clean up 
            finally:
                self.server_conn.close() # close the TCP connection to server 
        
        # discards all session material from memory so even if compromised later, there's nothing to recover 
        self.session_key = None
        self.token       = None
        self.cert_bytes  = None
        self.eph_priv    = None
        self.eph_pub_b   = None
        print("Logged out.")

    # COMMAND LOOP: reads user commands from stdin
    def run(self):
        print("Commands: list | send USER MESSAGE | exit | help")
        while True:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break # like the exit 

            if not line:
                continue # ignores empty input, shows prompt again 

            if line == "help":
                print("  list               – show online users")
                print("  send USER MESSAGE  – send an encrypted message")
                print("  exit               – log out and quit")

            elif line == "list":
                self.list_users()

            elif line.startswith("send "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Usage: send USER MESSAGE")
                else:
                    self.send_message(parts[1], parts[2])

            elif line == "exit":
                break # exit the loop, logout() called right after 

            else:
                print(f"Unknown command: '{line}'. Type 'help'.")

        self.logout()

# ENTRY POINT: decides whether to run as server or client 
if __name__ == "__main__":
        # sys.argv is list of command line args, sys.argv[0] is script name, sys.argv[1] shld be server or client 
    if len(sys.argv) < 2 or sys.argv[1] not in ("server", "client"):
        print("Usage:")
        print("  python3 secure_messenger.py server")
        print("  python3 secure_messenger.py client [server_host]")
        sys.exit(1)

    mode = sys.argv[1]
    # only server code runs, client class isn't used in memory 
    if mode == "server":
        run_server()
    # if remote server IP is provided as second arg, then it is used
    # otherwise default to localhost 127.0.0.1 for local testing 
    elif mode == "client":
         # only client code runs, server code isn't used in memory 
        host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        c = Client(host)
        c.login()
        c.run()
