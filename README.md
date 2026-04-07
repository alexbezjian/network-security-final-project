# Secure Messenger

A single-file secure peer-to-peer messaging system using X25519 Diffie-Hellman key exchange and AES-GCM encryption.

---

## Prerequisites

### Option A — Plain Python (Recommended)
Download and install Python 3.12 or higher from:
https://www.python.org/downloads

> During installation, make sure to check **"Add Python to PATH"**

### Option B — Anaconda Navigator 
Download and install Anaconda from:
https://www.anaconda.com/products/navigator

launch the Anaconda navigator and navigate to the anaconda_prompt 1.1.0 and launch 3 instances (2 clients, 1 server)  
---

## Installation

Open a terminal (CMD, PowerShell, or Anaconda Prompt) and install the required libraries:

```bash
pip install argon2-cffi
pip install cryptography
```

---

## Pre-Configured Users

| Username | Password   |
|----------|------------|
| alice    | alice123   |
| bob      | bob123     |
| albert   | albert123  |

---

## Usage

You will need **3 separate terminal windows** open at the same time. In each window, navigate to the folder containing `messenger.py`:

```bash
cd path/to/project/folder
```

### Terminal 1 — Start the Server

```bash
python messenger.py server
```

Expected output:
```
Server running on port 9000
```

Leave this window running. Do not close it.

### Terminal 2 — Start Client 1 (alice)

```bash
python messenger.py client
```

When prompted:
```
Username: alice
Password: alice123
Listening port: 9001
```

### Terminal 3 — Start Client 2 (bob)

```bash
python messenger.py client
```

When prompted:
```
Username: bob
Password: bob123
Listening port: 9002
```

### Optional: Terminal 4 — Start Client 3 (albert)

```bash
python messenger.py client
```

When prompted:
```
Username: albert
Password: albert123
Listening port: 9003
```

> Each client must use a **different listening port**. The server runs on port 9000, so clients start at 9001 and increment (9001, 9002, 9003, etc.).

---

## Commands

Once logged in, the following commands are available:

| Command              | Description                        |
|----------------------|------------------------------------|
| `list`               | Show all currently online users    |
| `send USER MESSAGE`  | Send an encrypted message to a user|
| `exit`               | Log out and close the client       |

### Example

```
list
send bob Hey, are you there?
send alice Hello back!
exit
```

---

## Restarting

1. Press `Ctrl+C` in each terminal window to stop all processes
2. Open 3 fresh terminal windows
3. Follow the Usage steps above again

---

## Troubleshooting

**"Module not found" error**
Run the pip install commands in the Installation section above.

**"Address already in use" error**
The server or a client is still running in another window. Close it and try again.

**"Login failed"**
Check that the username and password match the table above exactly. They are case-sensitive.

**"User not online"**
Make sure the recipient has logged in before you attempt to send them a message.

**Permission error on listening port**
Do not use ports below 1024. Use 9001, 9002, 9003, etc. for clients.
