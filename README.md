Compilation Instructions

Requirements:
- g++ (C++11 or later)
- openssl library (for SHA1 hashing in client)

Compile Tracker
    cd tracker
    g++ tracker.cpp -o tracker

Compile Client
    cd client
    g++ client.cpp -lssl -lcrypto -o client

Execution Instructions

Tracker Info File (tracker_info.txt)
    <IP1>:<PORT1>:<SYNC_PORT1>
    <IP2>:<PORT2>:<SYNC_PORT2>

Example:
    127.0.0.1:8005:9005
    127.0.0.1:8006:9006

Run Two Trackers
In two separate terminals:
    ./tracker tracker_info.txt 1
    ./tracker tracker_info.txt 2

Run Client
    ./client <IP:PORT> tracker_info.txt

Example:
    ./client 127.0.0.1:8005 tracker_info.txt

Quit Tracker
From a connected client/admin console:
    QUIT
This will stop the tracker gracefully.

Architectural Overview
- Tracker System (2 servers):
    - Maintains metadata for users, groups, and shared files.
    - Synchronizes state with peer tracker using SYNC and FULLSYNC messages.
    - Provides redundancy — system works as long as one tracker is alive.
- Client System:
    - CLI interface for user commands.
    - Acts as both downloader and seeder.
    - Runs a peer server to serve file pieces.
    - Supports multi-threaded piece-wise downloads with SHA1 verification.

Key Algorithms
- SHA1 Hashing:
    - File split into 512KB pieces.
    - Each piece hashed via SHA1; hashes sent to tracker.
    - Client verifies each downloaded piece before acceptance.
- Piece Selection Strategy:
    - Parallel strategy with sequential peer trial.
    - Each piece index assigned to a separate thread.
    - Each thread tries all peers until a valid SHA1 hash is received.
    - Ensures parallel utilization and avoids duplicates.
- Tracker Synchronization:
    - Incremental updates via SYNC|....
    - Full state replication on reconnect via FULLSYNC|....
- Group Management:
    - Owner manages join requests.
    - If owner leaves, group is dissolved.

Data Structures
Tracker:
- unordered_map<string, string> userlist → stores user credentials
- unordered_set<string> loggedIn → active sessions
- unordered_map<int, string> fd_to_user → maps socket fd → username
- vector<int> clients → list of connected client sockets
- unordered_map<string, unordered_set<string>> group_members → group → members
- unordered_map<string, unordered_set<string>> pending_requests → group → join requests
- unordered_map<string, string> group_owner → maps group to owner username
- unordered_map<string, unordered_map<string, FileMetadata>> group_files → file metadata (owner, filesize, piece hashes, seeders, path)
- queue<string> queue_list + queue_mutex + condition_variable queuelist_cv → queue of updates for tracker synchronization
- mutex users_mutex, group_mutex, groups_mutex, clients_mutex → concurrency protection

Client:
- unordered_map<string, shared_ptr<DownloadInfo>> activeDownloads → track progress.
- unordered_map<string, string> localFiles → shared files (filename → fullpath).
Chosen for fast lookups and thread safety with mutexes.

Network Protocol Design
TCP sockets used for all communication. Messages are newline-delimited.

Tracker ↔ Client Commands
- CREATE_USER|<username>|<password>
- LOGIN|<username>|<password>
- LOGOUT
- CREATE_GROUP|<group>
- JOIN_GROUP|<group>
- LEAVE_GROUP|<group>
- LIST_GROUPS
- LIST_REQUESTS|<group>
- ACCEPT_REQUESTS|<group>|<user>
- UPLOAD_FILE|<group>|<filename>|<filesize>|<hashes>|<port>
- LIST_FILES|<group>
- DOWNLOAD_FILE|<group>|<filename>
- STOP_SHARE|<group>|<filename>
- NEW_SEEDER|<filename>|<port>
- QUIT (tracker shutdown)

Tracker ↔ Tracker
- SYNC|... → incremental updates.
- FULLSYNC|... → full state replication.

Client ↔ Client
- GET_PIECE|<filename>|<piece_index>

Assumptions
- Files are identified uniquely within a group (by filename).
- Clients compute SHA1 hashes locally.
- Tracker only stores and distributes hashes, not files.
- Random port (10,000–20,000) chosen for each client’s peer server.
- Logout removes user session, but file seeding info may persist until STOP_SHARE.
- Group owner leaving dissolves the group entirely.

Implemented Features
- User authentication (create, login, logout)
- Group management (create, join, leave, accept requests, list)
- File upload (piece hashing, seeder registration)
- File listing and metadata distribution
- Parallel piece-wise file download with SHA1 verification
- Peer server for serving file pieces
- Automatic seeder registration after download
- Download progress reporting (show_downloads)
- Dual-tracker synchronization with redundancy



Testing Procedures
1. Tracker Startup
    - Start both trackers with tracker_info.txt.
    - Kill one tracker and verify the other continues operation.
    - Restart killed tracker → state resyncs via FULLSYNC.
2. User & Group Management
    - Create users, login, create/join groups.
    - Check group listings and request acceptance.
3. File Upload & Download
    - Client A uploads file.
    - Client B lists files and downloads them.
    - Verify SHA1 hash matches original file.
4. Multi-Peer Download
    - Two clients upload same file.
    - Third client downloads, pulling pieces from both simultaneously.
5. Stop Sharing
    - Client stops sharing file with stop_share.
    - Tracker no longer lists client as a seeder.
6. Quit Command
    - Send QUIT to tracker from a client console.
    - Verify tracker shuts down gracefully.
