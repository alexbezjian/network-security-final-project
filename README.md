Make sure that your submission includes a clear README on how to install your application (both the server and the client). 

The installation should be pre-configured for at least 3 users. The README should indicate the usernames and passwords of the authorized users.
__________________________________________________________________

Secure Messenger: A single-file secure peer-to-peer messaging system built from scratch using modern cryptographic primitives. 

* Download and install Python 3.12 or higher from: https://www.python.org/downloads
* open terminal and run: pip3 install cryptography argon2-cffi
* pre configured users:
    - Username: alice, Password: alice123
    - Username: bob, Password: bob123
    - Username: jill, Password: jill123

* at least 3 terminal windows open at a time. navigate each to the folder containing secure_messenger.py

* Terminal 1: start server
python3 secure_messenger.py server
Expected output: [server] Listening on port 9000
Leave this running, don't close it.

* Terminal 2: Client 1 (alice)
python3 secure_messenger.py client
When prompted enter:
    Username: alice
    Password: alice123
    Listening port (e.g. 9001): 9001

* Terminal 3: Client 2 (bob)
python3 secure_messenger.py client
When prompted enter:
    Username: bob
    Password: bob123
    Listening port (e.g. 9001): 9002

* Terminal 4: Client 3 (jill, optional)
python3 secure_messenger.py client
When prompted enter:
    Username: jill
    Password: jill123
    Listening port (e.g. 9001): 9003

Each client must use a different listening port. The server always runs on port 9000, so use 9001, 9002, 9003 for clients.

* Remote Server is also an option: 
    - if the server is running on a different machine, put its IP as an argument:
    python3 secure_messenger.py client 192.168.1.10

* Commands: once logged in, the following commands are available 
list — show all currently online users
send USER MESSAGE — send an end-to-end encrypted message to a user
exit — log out cleanly and close the client
help — show available commands

Example:
list
send bob Hey Bob, this is my message!
send alice Hey Alice!
exit

* Restarting
1. Press Ctrl+C in each terminal window to stop all processes
2. Open 3 fresh terminal windows
3. Follow the Usage steps above again