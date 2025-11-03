

# 🔗 Peer-to-Peer File Sharing System with Dual Tracker Synchronization

A lightweight BitTorrent-style peer-to-peer file sharing system built from scratch in **C++**, featuring **redundant dual-trackers**, **multi-threaded downloads**, **SHA1 integrity verification**, and **synchronized metadata replication** between trackers.

---

## 🧰 Requirements
- **g++ (C++11 or later)**
- **OpenSSL library** (for SHA1 hashing)

---

## ⚙️ Compilation Instructions

### Compile Tracker
```bash
cd tracker
g++ tracker.cpp -o tracker
````

### Compile Client

```bash
cd client
g++ client.cpp -lssl -lcrypto -o client
```

---

##  Execution Instructions

### Tracker Info File (`tracker_info.txt`)

```
<IP1>:<PORT1>:<SYNC_PORT1>
<IP2>:<PORT2>:<SYNC_PORT2>
```

**Example:**

```
127.0.0.1:8005:9005
127.0.0.1:8006:9006
```

### Run Two Trackers

In two separate terminals:

```bash
./tracker tracker_info.txt 1
./tracker tracker_info.txt 2
```

### Run Client

```bash
./client <IP:PORT> tracker_info.txt
```

**Example:**

```bash
./client 127.0.0.1:8005 tracker_info.txt
```

### Quit Tracker

From a connected client or admin console:

```
QUIT
```

Gracefully stops the tracker.

---

##  Architectural Overview

### Tracker System (2 servers)

* Maintains metadata for **users**, **groups**, and **shared files**.
* Synchronizes state with peer tracker using `SYNC` and `FULLSYNC` messages.
* Provides **redundancy** — system continues operation if one tracker fails.

### Client System

* CLI-based interface for user commands.
* Acts as both **downloader** and **seeder**.
* Runs a **peer server** to serve file pieces.
* Supports **multi-threaded piece-wise downloads** with **SHA1 verification**.

---

##  Key Algorithms

### 1. SHA1 Hashing

* Files are split into **512KB pieces**.
* Each piece is hashed using **SHA1**.
* Clients verify each piece after download to ensure data integrity.

### 2. Piece Selection Strategy

* **Parallel** download strategy with **sequential peer trials**.
* Each thread downloads one piece and verifies it using SHA1.
* Ensures efficient utilization and avoids duplicate downloads.

### 3. Tracker Synchronization

* **Incremental updates:** via `SYNC|...` messages.
* **Full state replication:** via `FULLSYNC|...` upon reconnect.
* Keeps both trackers in sync for fault tolerance.

### 4. Group Management

* Group owner manages join requests.
* If the owner leaves, the group is automatically **dissolved**.

---

##  Core Data Structures

### Tracker

| Type                                                         | Variable                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------- | ------------------------------------------------------------ |
| `unordered_map<string, string>`                              | `userlist`                                                    | Stores user credentials                                      |
| `unordered_set<string>`                                      | `loggedIn`                                                    | Active user sessions                                         |
| `unordered_map<int, string>`                                 | `fd_to_user`                                                  | Maps socket FD → username                                    |
| `vector<int>`                                                | `clients`                                                     | Connected client sockets                                     |
| `unordered_map<string, unordered_set<string>>`               | `group_members`                                               | Group → members                                              |
| `unordered_map<string, unordered_set<string>>`               | `pending_requests`                                            | Group → join requests                                        |
| `unordered_map<string, string>`                              | `group_owner`                                                 | Group → owner                                                |
| `unordered_map<string, unordered_map<string, FileMetadata>>` | `group_files`                                                 | File metadata (owner, filesize, piece hashes, seeders, path) |
| `queue<string>`                                              | `queue_list`                                                  | Queue of updates for tracker synchronization                 |
| `mutex`                                                      | `users_mutex`, `group_mutex`, `groups_mutex`, `clients_mutex` | Concurrency protection                                       |

### Client

| Type                                              | Variable          | Description                    |
| ------------------------------------------------- | ----------------- | ------------------------------ |
| `unordered_map<string, shared_ptr<DownloadInfo>>` | `activeDownloads` | Tracks ongoing downloads       |
| `unordered_map<string, string>`                   | `localFiles`      | Shared files (filename → path) |

---

##  Network Protocol Design

All communication uses **TCP sockets**, with **newline-delimited messages**.

### Tracker ↔ Client Commands

```
CREATE_USER|<username>|<password>
LOGIN|<username>|<password>
LOGOUT
CREATE_GROUP|<group>
JOIN_GROUP|<group>
LEAVE_GROUP|<group>
LIST_GROUPS
LIST_REQUESTS|<group>
ACCEPT_REQUESTS|<group>|<user>
UPLOAD_FILE|<group>|<filename>|<filesize>|<hashes>|<port>
LIST_FILES|<group>
DOWNLOAD_FILE|<group>|<filename>
STOP_SHARE|<group>|<filename>
NEW_SEEDER|<filename>|<port>
QUIT
```

### Tracker ↔ Tracker

```
SYNC|...       → Incremental updates
FULLSYNC|...   → Full state replication
```

### Client ↔ Client

```
GET_PIECE|<filename>|<piece_index>
```

---

##  Assumptions

* Files are **unique within each group** (by filename).
* Clients compute **SHA1 hashes locally**.
* Tracker stores only **metadata**, not file content.
* Each client chooses a **random port (10,000–20,000)** for its peer server.
* Logout removes session, but seeding info persists until `STOP_SHARE`.
* Group owner leaving **dissolves** the group.

---

##  Implemented Features

* User authentication (create, login, logout)
* Group management (create, join, leave, accept, list)
* File upload and seeder registration
* File listing and metadata sharing
* Parallel file downloads with SHA1 verification
* Peer-to-peer piece sharing
* Automatic seeder registration post-download
* Download progress tracking (`show_downloads`)
* Dual tracker synchronization with redundancy

---

##  Testing Procedures

### 1. Tracker Startup

* Start both trackers with `tracker_info.txt`.
* Kill one tracker → verify continued operation.
* Restart tracker → verify resynchronization via `FULLSYNC`.

### 2. User & Group Management

* Create users, login, create/join groups.
* Check group listings and request acceptance.

### 3. File Upload & Download

* Client A uploads a file.
* Client B downloads it.
* Verify SHA1 hash matches the original.

### 4. Multi-Peer Download

* Two clients share the same file.
* A third client downloads it from both simultaneously.

### 5. Stop Sharing

* Use `STOP_SHARE` to remove seeder info from tracker.

### 6. Tracker Shutdown

* Send `QUIT` command from a client console to stop tracker gracefully.

---
