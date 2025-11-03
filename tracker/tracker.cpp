
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <cstdlib>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <netdb.h>
#include <thread>
#include <vector>
#include <mutex>
#include <algorithm>
#include <condition_variable>
#include <fcntl.h>
#include <signal.h>

using namespace std;

//storing filedata
struct FileMetadata {
    string owner;//seeder who uploaded
    long filesize;//filesize
    vector<string> piece_hashes;//to store hashes
    unordered_map<string, string> seeders;  // username → "ip:port"
    string fullpath;  // store absolute path (optional)
};

// group → { filename → metadata }
unordered_map<string, unordered_map<string, FileMetadata>> group_files;
mutex group_mutex; // Protects access to group_files

vector<int> clients;
mutex clients_mutex;

//for users (userlist,loggedin,fdtouser)
unordered_map<string,string> userlist;
unordered_set<string> loggedIn;
unordered_map<int, string> fd_to_user;
mutex users_mutex; //for protecting userlist,loggedin,fduser

queue<string> queue_list;//for sending updates to other tracker
mutex queue_mutex;//for protecting queue list
condition_variable queuelist_cv;

//for groups
unordered_map<string, unordered_set<string>> group_members; // group_name -> members
unordered_map<string, unordered_set<string>> pending_requests;
unordered_map<string, string> group_owner;                  //for group permissions
mutex groups_mutex;                                        // protect group structures

// Completed downloads history (to display [C] group filename)
vector<string> completed_downloads;
mutex downloads_mutex; // protects completed_downloads

//trim spaces
string trim(const string &s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

vector<string> split(const string &s, char delimiter) {
    vector<string> tokens;
    string token;
    stringstream ss(s);

    while (getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

void handle_incoming_req(const string &msg) {
    vector<string> commands;
    stringstream ss(msg);
    string word;
    while (getline(ss, word, '|')) {
        commands.push_back(word);
    }

    if (commands.size() < 2) return;

    string type = trim(commands[0]);
    string cmd = trim(commands[1]);

    if (type == "SYNC") {
        if (cmd == "CREATE_USER" && commands.size() >= 4) {
            string username = commands[2];
            string password = commands[3];
            lock_guard<mutex> lock(users_mutex);
            if (userlist.find(username) == userlist.end())
                userlist[username] = password;
            cout << "[SYNC] User created: " << username << endl;
        }
        else if (cmd == "LOGIN" && commands.size() >= 3) {
            string username = trim(commands[2]);
            lock_guard<mutex> lock(users_mutex);
            loggedIn.insert(username);
            cout << "[SYNC] User logged in: " << username << endl;
        }
        else if (cmd == "LOGOUT" && commands.size() >= 3) {
            string username = trim(commands[2]);
            lock_guard<mutex> lock(users_mutex);
            loggedIn.erase(username);
            cout << "[SYNC] User logged out: " << username << endl;
        }
        else if (cmd == "CREATE_GROUP" && commands.size() >= 4) {
            string group = trim(commands[2]);
            transform(group.begin(), group.end(), group.begin(), ::tolower);
            string owner = trim(commands[3]);
            lock_guard<mutex> lock(groups_mutex);
            if (group_members.find(group) == group_members.end()) {
                group_members[group].insert(owner);
                group_owner[group] = owner;
                cout << "[SYNC] Group created: " << group << endl;
            }
        }
        else if (cmd == "JOIN_GROUP" && commands.size() >= 4) {
            string group = trim(commands[2]);
            transform(group.begin(), group.end(), group.begin(), ::tolower);
            string username = trim(commands[3]);
            lock_guard<mutex> lock(groups_mutex);
            pending_requests[group].insert(trim(username));
            cout << "[SYNC] " << username << " requested to join " << group << endl;
        }
        else if (cmd == "ACCEPT_REQUEST" && commands.size() >= 4) {
            string group = commands[2];
            transform(group.begin(), group.end(), group.begin(), ::tolower);
            string username = commands[3];
            lock_guard<mutex> lock(groups_mutex);
            group_members[group].insert(username);
            pending_requests[group].erase(trim(username));
            cout << "[SYNC] " << username << " accepted into " << group << endl;
        }
        else if (cmd == "LEAVE_GROUP" && commands.size() >= 4) {
            string group = trim(commands[2]);
            transform(group.begin(), group.end(), group.begin(), ::tolower);
            string username = trim(commands[3]);
            lock_guard<mutex> lock(groups_mutex);
            group_members[group].erase(username);
            cout << "[SYNC] " << username << " left " << group << endl;
        }
        else if (cmd == "UPLOAD_FILE" && commands.size() >= 8) {
            string group = trim(commands[2]);
            transform(group.begin(), group.end(), group.begin(), ::tolower);
            string filename = trim(commands[3]);
            long filesize = stol(commands[4]);
            vector<string> hashes = split(commands[5], ',');
            string username = trim(commands[6]);
            string ip_port = trim(commands[7]);   

            lock_guard<mutex> lock(group_mutex);
            auto &file_map = group_files[group];
            auto it = file_map.find(filename);

            if(it != file_map.end()) {
            
                it->second.seeders[username] = ip_port;
            } else {
                FileMetadata meta;
                meta.owner = username;
                meta.filesize = filesize;
                meta.piece_hashes = hashes;
                meta.seeders[username] = ip_port;
                file_map[filename] = meta;
            }

            cout << "[SYNC] File uploaded: " << filename
                 << " in group " << group
                 << " by " << username
                 << " (" << ip_port << ")" << endl;
        }
        else if (cmd == "STOP_SHARE" && commands.size() >= 5) {
            string group = trim(commands[2]);
            transform(group.begin(), group.end(), group.begin(), ::tolower);
            string filename = trim(commands[3]);
            string username = trim(commands[4]);

            lock_guard<mutex> lock(group_mutex);
            if (group_files.find(group) != group_files.end() &&
                group_files[group].find(filename) != group_files[group].end()) {
                group_files[group][filename].seeders.erase(username);
                cout << "[SYNC] User " << username
                     << " stopped sharing file " << filename << endl;
            }
        }
        else if (cmd == "NEW_SEEDER" && commands.size() >= 6) {
            string group    = commands[2];
            transform(group.begin(), group.end(), group.begin(), ::tolower);
            string filename = commands[3];
            string username = commands[4];
            string ip_port  = commands[5];

            lock_guard<mutex> lock(group_mutex);
            auto &file_map = group_files[group];  
            auto it = file_map.find(filename);

            if(it != file_map.end()) {
                it->second.seeders[username] = ip_port;
            } else {
                FileMetadata meta;
                meta.seeders[username] = ip_port;
                file_map[filename] = meta;
                cout << "[SYNC] File " << filename << " created for NEW_SEEDER from " << username << endl;
            }

            cout << "[SYNC] New seeder " << username << " added for file " << filename
                 << " in group " << group << " (" << ip_port << ")" << endl;
        }
        else if (cmd == "DOWNLOAD_COMPLETE" && commands.size() >= 5) {
            string group = trim(commands[2]);
            transform(group.begin(), group.end(), group.begin(), ::tolower);
            string filename = trim(commands[3]);
            string username = trim(commands[4]);

            lock_guard<mutex> lock(downloads_mutex);
            string entry = "[C] " + group + " " + filename + " (by " + username + ")";
            completed_downloads.push_back(entry);
            cout << "[SYNC] Download complete registered: " << entry << endl;
          
        }
    } else if (type == "FULLSYNC") {
        if (cmd == "USER" && commands.size() >= 4) {
            string username = trim(commands[2]);
            string password = trim(commands[3]);
            lock_guard<mutex> lock(users_mutex);
            userlist[username] = password;
        }
        else if (cmd == "LOGIN" && commands.size() >= 3) {
            string username = trim(commands[2]);
            lock_guard<mutex> lock(users_mutex);
            loggedIn.insert(username);
        }
        else if (cmd == "GROUP" && commands.size() >= 4) {
            string group = trim(commands[2]);
            string owner = trim(commands[3]);
            lock_guard<mutex> lock(groups_mutex);
            group_members[group].insert(owner);
            group_owner[group] = owner;
        }
        else if (cmd == "JOIN" && commands.size() >= 4) {
            string group = trim(commands[2]);
            string username = trim(commands[3]);
            lock_guard<mutex> lock(groups_mutex);
            group_members[group].insert(username);
        }
        else if (cmd == "REQUEST" && commands.size() >= 4) {
            string group = commands[2];
            string username = commands[3];
            lock_guard<mutex> lock(groups_mutex);
            pending_requests[group].insert(trim(username));
        }
        else if (cmd == "FILE" && commands.size() >= 7) {
            string group = trim(commands[2]);
            transform(group.begin(), group.end(), group.begin(), ::tolower);
            string filename = trim(commands[3]);
            long filesize = stol(commands[4]);
            vector<string> hashes = split(commands[5], ',');
            string seeders_str = trim(commands[6]);

            lock_guard<mutex> lock(group_mutex);
            FileMetadata meta;
            meta.owner = "";           
            meta.filesize = filesize;
            meta.piece_hashes = hashes;

            if (!seeders_str.empty()) {
                vector<string> seeder_list = split(seeders_str, ',');
                for (auto &entry : seeder_list) {
                    
                    size_t atpos = entry.find('@');
                    if (atpos == string::npos) continue;
                    string username = entry.substr(0, atpos);
                    string ip_port = entry.substr(atpos + 1);
                    meta.seeders[username] = ip_port;
                }
            }

        
            if (group_files[group].find(filename) != group_files[group].end()) {
                auto &existing = group_files[group][filename];
        
                for (auto &p : meta.seeders) existing.seeders[p.first] = p.second;
            
            } else {
                group_files[group][filename] = meta;
            }

            cout << "[FULLSYNC] Received file " << filename << " for group " << group << " with "
                 << group_files[group][filename].seeders.size() << " seeders.\n";
        }
    }
}

void send_full_state(int sock_fd) {
    // Send all users and logins
    {
        lock_guard<mutex> lock(users_mutex);
        for (auto &u : userlist) {
            string msg = "FULLSYNC|USER|" + u.first + "|" + u.second + "\n";
            send(sock_fd, msg.c_str(), msg.size(), 0);
        }
        for (auto &u : loggedIn) {
            string msg = "FULLSYNC|LOGIN|" + u + "\n";
            send(sock_fd, msg.c_str(), msg.size(), 0);
        }
    }

    //  Send groups, members, and requests
    {
        lock_guard<mutex> lock(groups_mutex);
        for (auto &g : group_members) {
            string owner = group_owner[g.first];
            string msg = "FULLSYNC|GROUP|" + g.first + "|" + owner + "\n";
            send(sock_fd, msg.c_str(), msg.size(), 0);

            // send confirmed members only
            for (auto &member : g.second) {
                if (pending_requests.find(g.first) == pending_requests.end() ||
                     pending_requests[g.first].count(member) == 0) {
                    string m = "FULLSYNC|JOIN|" + g.first + "|" + member + "\n";
                    send(sock_fd, m.c_str(), m.size(), 0);
                }
            }

            // send pending requests
            for (auto &user : pending_requests[g.first]) {
                string r = "FULLSYNC|REQUEST|" + g.first + "|" + user + "\n";
                send(sock_fd, r.c_str(), r.size(), 0);
            }
        }
    }
    // Send files & seeders
    {
        lock_guard<mutex> lock(group_mutex);
        for (auto &gpair : group_files) {
            const string &group = gpair.first;
            for (auto &fpair : gpair.second) {
                const string &filename = fpair.first;
                const FileMetadata &meta = fpair.second;

                // join piece hashes
                string hashlist;
                for (size_t i = 0; i < meta.piece_hashes.size(); ++i) {
                    hashlist += meta.piece_hashes[i];
                    if (i + 1 < meta.piece_hashes.size()) hashlist += ",";
                }

                
                string seeder_str;
                for (auto &s : meta.seeders) {
                    seeder_str += s.first + "@" + s.second + ",";
                }
                if (!seeder_str.empty() && seeder_str.back() == ',') seeder_str.pop_back();

                string msg = "FULLSYNC|FILE|" + group + "|" + filename + "|" + to_string(meta.filesize)
                             + "|" + hashlist + "|" + seeder_str + "\n";
                send(sock_fd, msg.c_str(), msg.size(), 0);
            }
        }
    }

}

void sendmsg(vector<string> &commands){
    // Build message
    string msg = "SYNC|";
    for(size_t i = 0; i < commands.size(); i++){
        msg += commands[i];
        if(i < commands.size() - 1) msg += "|";
    }
    msg += "\n";

    // Queue the message
    {
        lock_guard<mutex> lock(queue_mutex);
        queue_list.push(msg);
    }
    queuelist_cv.notify_one();
}

void syn_sender(int port, string ip) {
    int sock_snd;

    struct sockaddr_in synsnd;
    synsnd.sin_family = AF_INET;
    synsnd.sin_port = htons(port);
    if(inet_pton(AF_INET, ip.c_str(), &synsnd.sin_addr) <= 0){
        perror("Invalid peer tracker IP address");
        exit(1);
    }

    // Initial connection loop
    while(true){
        sock_snd = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_snd < 0){ perror("socket creation failed"); exit(1); }

        if(connect(sock_snd, (struct sockaddr*)&synsnd, sizeof(synsnd)) < 0){
            perror("Connection to peer tracker failed, retrying...");
            sleep(1);
        } else {
            printf("Tracker connected to peer tracker at %d %s\n", port, ip.c_str());
            send_full_state(sock_snd);
            break;
        }
    }

    // Main sender loop
    while(true){
        string msg;
        {
            unique_lock<mutex> lock(queue_mutex);
            while(queue_list.empty()){
                queuelist_cv.wait(lock);
            }
            msg = queue_list.front();
            queue_list.pop();
        }

        int n = send(sock_snd, msg.c_str(), msg.size(), 0);
        if(n <= 0){
            close(sock_snd);

            // push back message for retry
            {
                lock_guard<mutex> lock(queue_mutex);
                queue_list.push(msg);
            }
            queuelist_cv.notify_one();

            // reconnect
            sock_snd = socket(AF_INET, SOCK_STREAM, 0);
            if(sock_snd < 0){ perror("socket creation failed"); continue; }

            if(connect(sock_snd, (struct sockaddr*)&synsnd, sizeof(synsnd)) < 0){
                perror("Reconnection to peer tracker failed, retrying...");
                sleep(1);
                continue;
            } else {
                printf("Tracker reconnected to peer tracker at %d %s\n", port, ip.c_str());
                send_full_state(sock_snd);
                continue;
            }
        }
    }
}

void syn_listener(int port, string ip) {
    int sock_lis = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_lis < 0) {
        perror("cant create socket");
        exit(1);
    }

    struct sockaddr_in synlsn;
    synlsn.sin_family = AF_INET;
    synlsn.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &synlsn.sin_addr) <= 0) {
        perror("Invalid IP address of peer tracker");
        exit(1);
    }

    if (bind(sock_lis, (struct sockaddr*)&synlsn, sizeof(synlsn)) < 0) {
        perror("cant bind to peer tracker");
        exit(1);
    }

    listen(sock_lis, 5);
    printf("Tracker listening for peer tracker on port %d...\n", port);

    while (true) {
        struct sockaddr_in peer;
        socklen_t len = sizeof(peer);

        int fd = accept(sock_lis, (struct sockaddr*)&peer, &len);
        if (fd < 0) {
            perror("Error on peer tracker accept");
            continue;
        }

        printf("Peer tracker connected.\n");

        string buffer;  // persistent buffer for partial data
        char buff[1024];

        while (true) {
            int n = recv(fd, buff, sizeof(buff) - 1, 0);
            if (n <= 0) {
                printf("Peer tracker disconnected, waiting again...\n");
                close(fd);
                break; // go back to accept()
            }
            buff[n] = '\0';
            buffer += buff;  

            // process complete lines
            size_t pos;
            while ((pos = buffer.find('\n')) != string::npos) {
                string line = buffer.substr(0, pos);
                buffer.erase(0, pos + 1);

                if (!line.empty()) {
                    handle_incoming_req(line);
                }
            }
        }
    }
}


void create_user(vector<string> &commands, int fd) {
    if (commands.size() < 3) {
        string reply = "ERR|Usage: CREATE_USER|<username>|<password>\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }

    string username = commands[1];
    string password = commands[2];
    {
       lock_guard<mutex> lock(users_mutex);
       if (userlist.find(username) != userlist.end()) {
           string reply = "ERR|User already exists\n";
           send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
           return;
       }

       userlist[username] = password;
    }

    string reply = "OK|User " + username + " created\n";
    send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);

    vector<string> sync_cmd = {"CREATE_USER", username, password};
    sendmsg(sync_cmd);
}


void login(vector<string> &commands,int fd){
    if(commands.size() < 3){
        string reply = "ERR|Usage: LOGIN|<username>|<password>\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }
    string username = trim(commands[1]);
    string password = trim(commands[2]);

    {
        lock_guard<mutex> lock(users_mutex);
        if(userlist.find(username)== userlist.end()){
            string reply = "ERR|User does not exist\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            return;
        }

        if (fd_to_user.find(fd) != fd_to_user.end()) {
            string reply = "ERR|Already logged in on this terminal\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }

        if(userlist[username]==password){
            if(loggedIn.find(username)!=loggedIn.end()){
                string reply = "ERR|User Already Logged In\n";
                send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
                return ;
            }
            loggedIn.insert(username);
            fd_to_user[fd] = username;
            string reply = "OK|Login success for " + commands[1] + "\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            vector<string> sync_cmd = {"LOGIN", username};
            sendmsg(sync_cmd);
            return;
        } else {
            string reply = "ERR|Incorrect Credentials\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            return;
        }
    }
}

void logout(vector<string> &commands,int fd){
    lock_guard<mutex> lock(users_mutex);

    if(fd_to_user.find(fd)!=fd_to_user.end()){
        string username = fd_to_user[fd];
        loggedIn.erase(username);
        fd_to_user.erase(fd);
        string reply = "OK|Logged out " + username + "\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        vector<string> sync_cmd = {"LOGOUT", username};
        sendmsg(sync_cmd);
    }
    else{
        string reply  = "ERR|User is not present\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
    }
}

void create_group(vector<string> &commands,int fd){

    if(commands.size()<2){
        string reply = "ERR|Usage: CREATE_GROUP|<groupname>\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }
    {
        lock_guard<mutex> lock(users_mutex);
        if(fd_to_user.find(fd) == fd_to_user.end()) {
            string reply = "ERR|Please login first\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }
    }
    string username;
    {
        lock_guard<mutex> lock(users_mutex);
        username = fd_to_user[fd];
    }

    if(loggedIn.find(username)==loggedIn.end()){
        string reply = "ERR|User should login inorder to create group\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }
    string groupname = commands[1];
    transform(groupname.begin(), groupname.end(), groupname.begin(), ::tolower);
    {
        lock_guard<mutex> lock(groups_mutex);

        if (group_members.find(groupname)!=group_members.end() ||
            pending_requests.find(groupname)!=pending_requests.end()) {
            string reply = "ERR|Group already present\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            return;
        }

        group_members[groupname].insert(username);
        group_owner[groupname] = username;

    }

    string reply = "OK|Group created " + commands[1] + "\n";
    send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);

    vector<string> sync_cmd = {"CREATE_GROUP", groupname, username};
    sendmsg(sync_cmd);

}
void join_group(vector<string> &commands,int fd){
    if(commands.size()<2){
        string reply = "ERR|Usage: JOIN_GROUP|<groupname>\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }

    {
        lock_guard<mutex> lock(users_mutex);
        if(fd_to_user.find(fd) == fd_to_user.end()){
            string reply = "ERR|Please login first\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }
    }

    string username;
    {
        lock_guard<mutex> lock(users_mutex);
        username = trim(fd_to_user[fd]);
    }

    if(loggedIn.find(username)==loggedIn.end()){
        string reply = "ERR|User should login inorder to join group\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }

    string groupname = trim(commands[1]);
    transform(groupname.begin(), groupname.end(), groupname.begin(), ::tolower);
    {
        lock_guard<mutex> lock(groups_mutex);

        if(group_members.find(groupname)==group_members.end()){
            string reply = "ERR|Group does not exist\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            return;
        }

        if(group_members[groupname].find(username)!=group_members[groupname].end()){
            string reply = "ERR|User is already present in the group\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            return;
        }

        // add pending request if not already present
        if (!pending_requests[groupname].count(username)) {
            pending_requests[groupname].insert(trim(username));
        }
    }

    string reply = "OK|Group join request sent for " + commands[1] + "\n";
    send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
    vector<string> sync_cmd = {"JOIN_GROUP", groupname, username};
    sendmsg(sync_cmd);
}

void accept_requests(vector<string> &commands,int fd){
    if(commands.size()<3){
        string reply = "ERR|Usage: ACCEPT_REQUEST|<groupname>|<username_to_accept>\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }

    string groupname = trim(commands[1]);
    transform(groupname.begin(), groupname.end(), groupname.begin(), ::tolower);

    string target_user = trim(commands[2]);
    {
        lock_guard<mutex> lock(users_mutex);
        if(fd_to_user.find(fd) == fd_to_user.end()){
            string reply = "ERR|Please login first\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }
    }
    string username;
    {
        lock_guard<mutex> lock(users_mutex);
        username = trim(fd_to_user[fd]);
    }

    if(loggedIn.find(username)==loggedIn.end()){
        string reply = "ERR|User should login inorder to create group\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }

    {
        lock_guard<mutex> lock(groups_mutex);

        if(group_members.find(groupname)==group_members.end()){
            string reply ="ERR|Group Does Not Exist\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }

        if (group_owner[groupname] != username) {
            string reply = "ERR|Permission Denied (only owner can accept requests)\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }


        auto &reqs = pending_requests[groupname];
        if (reqs.count(target_user) == 0) {
            string reply = "ERR|No pending request from user " + target_user + "\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            return;
        }

        reqs.erase(target_user);
        group_members[groupname].insert(target_user);
    }

    string reply = "OK|request accepted " + commands[1] +"\n";
    send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);

    vector<string> sync_cmd = {"ACCEPT_REQUEST", groupname, target_user};
    sendmsg(sync_cmd);
}


void leave_group(vector<string> &commands,int fd){

    if(commands.size()<2){
        string reply = "ERR|Usage: LEAVE_GROUP|<groupname>\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }

    string username;
    {
        lock_guard<mutex> lock(users_mutex);
        username = fd_to_user[fd];
    }

    if(loggedIn.find(username)==loggedIn.end()){
        string reply = "ERR|User should login inorder to leave group\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }
    string groupname = commands[1];
    transform(groupname.begin(), groupname.end(), groupname.begin(), ::tolower);

    {
        lock_guard<mutex> lock(groups_mutex);

        if(group_members.find(groupname)==group_members.end()){
            string reply = "ERR|Group does not exist\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            return;
        }

        if(group_members[groupname].find(username)==group_members[groupname].end()){
            string reply  = "ERR|User is Not a member of the group\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            return;
        }


        if(group_owner[groupname] == username){
            group_members.erase(groupname);
            pending_requests.erase(groupname);
            group_owner.erase(groupname);

            string reply = "OK|Group " + groupname + " dissolved (owner left)\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }

        group_members[groupname].erase(username);
        vector<string> sync_cmd = {"LEAVE_GROUP", groupname, username};
        sendmsg(sync_cmd);

    }

    string reply = "OK|You left the group " + groupname + "\n";
    send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);


}
void list_groups(vector<string> &commands,int fd){

    string username;
    {
        lock_guard<mutex> lock(users_mutex);
        username = fd_to_user[fd];
    }

    if(loggedIn.find(username)==loggedIn.end()){
        string reply = "ERR|User should login inorder to list group\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }
    {
        lock_guard<mutex> lock(groups_mutex);
        if(group_members.empty()){
            string reply = "OK|No Groups are persent currently\n";
            send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
            return;
        }
        string reply = "OK ";
        for(auto group:group_members){
            reply += group.first +", ";
        }
        if(reply.size() >= 2){
            reply.pop_back();  
            reply.pop_back();  
        }
        reply += "\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
    }
}
void list_requests(vector<string> &commands,int fd){
    if(commands.size()<2){
        string reply = "ERR|usage: LIST_REQUESTS|<groupname>\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }

    {
        lock_guard<mutex> lock(users_mutex);
        if(fd_to_user.find(fd) == fd_to_user.end()){
            string reply = "ERR|Please login first\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }
    }
    string username;
    {
        lock_guard<mutex> lock(users_mutex);
        username  = fd_to_user[fd];
    }

    if(loggedIn.find(username)==loggedIn.end()){
        string reply = "ERR|User is not logged in\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
        return;
    }

    string groupname = commands[1];
    transform(groupname.begin(), groupname.end(), groupname.begin(), ::tolower);

    {
        lock_guard<mutex> lock(groups_mutex);

        if (group_members.find(groupname) == group_members.end()) {
            string reply = "ERR|Group does not exist\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }

        if (group_owner[groupname] != username) {
            string reply = "ERR|Permission Denied (only owner can list requests)\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }

        if (pending_requests[groupname].empty()) {
            string reply = "OK|No pending requests for " + groupname + "\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }

        string reply = "OK ";
        for(const auto &usr : pending_requests[groupname]){
            reply += usr + ", ";
        }

        if(!pending_requests[groupname].empty()){
            reply.pop_back(); 
            reply.pop_back(); 
        }
        reply += "\n";
        send(fd, reply.c_str(), reply.size(),MSG_NOSIGNAL);
    }
}

// UPLOAD FILE
void upload_file(vector<string> &commands, int fd) {
    if(commands.size() < 6) {
        string reply = "ERR|Usage: UPLOAD_FILE|<group>|<filename>|<filesize>|<hash1,hash2,...>|<listen_port>\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
        return;
    }

    {
        lock_guard<mutex> lock(users_mutex);
        if(fd_to_user.find(fd) == fd_to_user.end()) {
            string reply = "ERR|Please login first\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }
    }
    string username;
    {
        lock_guard<mutex> lock(users_mutex);
        username = fd_to_user[fd];
    }

    string group = trim(commands[1]);
    transform(group.begin(), group.end(), group.begin(), ::tolower);
    string filename = trim(commands[2]);
    long filesize = stol(commands[3]);
    vector<string> hashes = split(commands[4], ',');
    string listen_port = trim(commands[5]);

    // get ip
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getpeername(fd, (struct sockaddr*)&addr, &len);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
    string ip_port = string(ip_str) + ":" + listen_port;

    {
        lock_guard<mutex> lock(group_mutex);
        auto &file_map = group_files[group];
        auto it = file_map.find(filename);

        if(it != file_map.end()) {
            it->second.seeders[username] = ip_port;
        } else {
            FileMetadata meta;
            meta.owner = username;
            meta.filesize = filesize;
            meta.piece_hashes = hashes;
            meta.seeders[username] = ip_port;
            file_map[filename] = meta;
        }
    }

    string reply = "OK|File uploaded successfully\n";
    send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);


    vector<string> syncmsg = {"UPLOAD_FILE", group, filename, to_string(filesize), commands[4], username, ip_port};
    sendmsg(syncmsg);
}



// STOP SHARE FILE
void stop_share(vector<string> &commands, int fd) {
    if(commands.size() < 3) {
        string reply = "ERR|Usage: STOP_SHARE|<group>|<filename>\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
        return;
    }

    {
        lock_guard<mutex> lock(users_mutex);
        if(fd_to_user.find(fd) == fd_to_user.end()) {
            string reply = "ERR|Please login first\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }
    }
    string username;
    {
        lock_guard<mutex> lock(users_mutex);
        username = fd_to_user[fd];
    }

    string group = trim(commands[1]);
    string filename = trim(commands[2]);

    bool file_found = false;

    {
        lock_guard<mutex> lock(group_mutex);

        auto git = group_files.find(group);
        if(git != group_files.end()) {
            auto fit = git->second.find(filename);
            if(fit != git->second.end()) {
                fit->second.seeders.erase(username);
                file_found = true;
            }
        }
    }

    if(file_found) {
        string reply = "OK|Stopped sharing file\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);

        
        vector<string> syncmsg = {"STOP_SHARE", group, filename, username};
        sendmsg(syncmsg);
    } else {
        string reply = "ERR|File not found\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
    }
}

void download_file(vector<string> &commands, int fd) {
    if (commands.size() < 3) {
        string reply = "ERR|Usage: DOWNLOAD_FILE|<group>|<filename>\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
        return;
    }

    {
        lock_guard<mutex> lock(users_mutex);
        if(fd_to_user.find(fd) == fd_to_user.end()) {
            string reply = "ERR|Please login first\n";
            send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            return;
        }
    }

    string group = trim(commands[1]);
    transform(group.begin(), group.end(), group.begin(), ::tolower);
    string filename = trim(commands[2]);

    FileMetadata filemeta;
    bool found = false;

    {
        lock_guard<mutex> lock(group_mutex);
        auto git = group_files.find(group);
        if (git != group_files.end()) {
            auto fit = git->second.find(filename);
            if (fit != git->second.end()) {
                filemeta = fit->second; 
                found = true;
            }
        }
    }

    if (!found) {
        string reply = "ERR|File not found in group\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
        return;
    }

    if (filemeta.seeders.empty()) {
        string reply = "ERR|No active seeders available\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
        return;
    }

    // Construct reply
    string reply = "OK|" + filename + "|" + to_string(filemeta.filesize) + "|";

    
    for (size_t i = 0; i < filemeta.piece_hashes.size(); i++) {
        reply += filemeta.piece_hashes[i];
        if (i + 1 < filemeta.piece_hashes.size()) reply += ",";
    }

    reply += "|";

    
    for (auto &s : filemeta.seeders) {
        reply += s.first + "@" + s.second + ",";
    }
    if (!filemeta.seeders.empty() && reply.back() == ',') reply.pop_back();

    reply += "\n";

    send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
}

string join(const vector<string>& v, char delimiter) {
    string s;
    for(size_t i=0; i<v.size(); i++) {
        s += v[i];
        if(i+1 < v.size()) s += delimiter;
    }
    return s;
}


// LIST FILES
void list_files(vector<string> &commands, int fd) {
    if(commands.size() < 2) {
        string reply = "ERR|Usage: LIST_FILES|<group>\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
        return;
    }

    string group = trim(commands[1]);
    string reply = "OK|";

    {
        lock_guard<mutex> lock(group_mutex);

        auto git = group_files.find(group);
        if(git == group_files.end() || git->second.empty()) {
            reply += "No files";
        } else {
            bool hasFiles = false;
            for(auto &f : git->second) {
                if(!f.second.seeders.empty()) {  // only files with seeders
                    reply += f.first + ",";
                    hasFiles = true;
                }
            }
            if(!hasFiles) reply += "No files";
            else if(reply.back() == ',') reply.pop_back();
        }
    }

    reply += "\n";
    send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
}

void new_seeder(vector<string> &commands, int fd) {
    
    if(commands.size() < 5) {
        string reply = "ERR|Usage: NEW_SEEDER|<group>|<filename>|<username>|<ip:port>\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
        return;
    }

    string group = trim(commands[1]);
    transform(group.begin(), group.end(), group.begin(), ::tolower);
    string filename = trim(commands[2]);
    string username = trim(commands[3]);
    string ip_port = trim(commands[4]);

    lock_guard<mutex> lock(group_mutex);
    auto &file_map = group_files[group];
    auto it = file_map.find(filename);
    if(it != file_map.end()) {
        it->second.seeders[username] = ip_port;
    } else {
        FileMetadata meta;
        meta.seeders[username] = ip_port;
        file_map[filename] = meta;
    }

    string reply = "OK|New seeder recorded\n";
    send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);

    vector<string> syncmsg = {"NEW_SEEDER", group, filename, username, ip_port};
    sendmsg(syncmsg);
}


void show_downloads(vector<string> &commands, int fd) {
    lock_guard<mutex> lock(downloads_mutex);
    if(completed_downloads.empty()) {
        string reply = "OK|No completed downloads\n";
        send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
        return;
    }
    string reply = "OK|";
    for(auto &s : completed_downloads) {
        reply += s + ";";
    }
    reply += "\n";
    send(fd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
}

// Handle peer connections
void handlepeers(int newsfd) {
    char buf[4096];
    static unordered_map<int, string> client_buffers; 

    while (true) {
        int n = recv(newsfd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) { 
            break;
        }
        buf[n] = '\0';
        client_buffers[newsfd] += buf;

        size_t pos;
        while ((pos = client_buffers[newsfd].find('\n')) != string::npos) {
            string msg = client_buffers[newsfd].substr(0, pos);
            client_buffers[newsfd].erase(0, pos + 1);

            if (msg.empty()) continue;

            {
                lock_guard<mutex> lock(clients_mutex);
                cout << "Client[" << newsfd << "]: " << msg << endl;
                cout.flush();
            }

        
            stringstream ss2(msg);
            string command;
            vector<string> commands;
            while (getline(ss2, command, '|')) {
                command = trim(command);
                if (!command.empty()) commands.push_back(command);
            }

            if (commands.empty()) continue;

            if (commands[0] == "CREATE_USER") {
                create_user(commands, newsfd);
            }
            else if (commands[0] == "LOGIN") {
                login(commands, newsfd);
            }
            else if (commands[0] == "CREATE_GROUP") {
                create_group(commands, newsfd);
            }
            else if (commands[0] == "JOIN_GROUP") {
                join_group(commands, newsfd);
            }
            else if (commands[0] == "LEAVE_GROUP") {
                leave_group(commands, newsfd);
            }
            else if (commands[0] == "LIST_GROUPS") {
                list_groups(commands, newsfd);
            }
            else if (commands[0] == "LIST_REQUESTS") {
                list_requests(commands, newsfd);
            }
            else if (commands[0] == "ACCEPT_REQUEST" || commands[0] == "ACCEPT_REQUESTS") {
                accept_requests(commands, newsfd);
            }
            else if (commands[0] == "LOGOUT") {
                logout(commands, newsfd);
            }
            else if (commands[0] == "UPLOAD_FILE") {
                upload_file(commands, newsfd);
            }
            else if (commands[0] == "STOP_SHARE") {
                stop_share(commands, newsfd);
            }
            else if (commands[0] == "LIST_FILES") {
                list_files(commands, newsfd);
            }
            else if (commands[0] == "DOWNLOAD_FILE") {
                download_file(commands, newsfd);
            }
            else if (commands[0] == "NEW_SEEDER") {
                new_seeder(commands, newsfd);
            }
            else if (commands[0] == "SHOW_DOWNLOADS") {
                show_downloads(commands, newsfd);
            }
            else if (commands[0] == "DOWNLOAD_COMPLETE") {
                handle_incoming_req("SYNC|DOWNLOAD_COMPLETE|" + 
                                    (commands.size() >= 4 ? commands[1] + "|" + commands[2] + "|" + (commands.size() >= 5 ? commands[3] : "") : ""));
                string reply = "OK|Download completion recorded\n";
                send(newsfd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            }
            else if (commands[0] == "QUIT") {
                string reply = "OK|Tracker shutting down\n";
                send(newsfd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
                cout << "[Tracker] Received QUIT command. Shutting down..." << endl;
                exit(0);
            }
            else {
                string reply = "ERR|Unknown command\n";
                send(newsfd, reply.c_str(), reply.size(), MSG_NOSIGNAL);
            }
        }
    }

    
    {
        lock_guard<mutex> lock(clients_mutex);
        clients.erase(remove(clients.begin(), clients.end(), newsfd), clients.end());
    }
    {
        lock_guard<mutex> lock(users_mutex);
        if (fd_to_user.find(newsfd) != fd_to_user.end()) {
            string username = fd_to_user[newsfd];
            fd_to_user.erase(newsfd);
            loggedIn.erase(username);
        }
    }

    client_buffers.erase(newsfd); 
    close(newsfd);
}

int main(int argc , char* argv[]){
    signal(SIGPIPE, SIG_IGN);
    if(argc<3){
        perror("Usage: ./tracker tracker_info.txt tracker_no");
        exit(1);
    }

    const char* file = argv[1];
    int tacknum = atoi(argv[2]);

    int fd = open(file,O_RDONLY);
    if(fd<0){
        perror("Cant open tracker_info file");
        exit(1);
    }

    char buffer[4096];
    int bytes = read(fd, buffer, sizeof(buffer) - 1);
    buffer[bytes] = '\0';
    close(fd);

    if (bytes <= 0) {
        perror("Error reading file or empty file");
        return 1;
    }

    string fileContent(buffer);
    stringstream fileStream(fileContent);

    string line;

    vector<string> ipadd;
    vector<int> ports;

    while(getline(fileStream,line)){
        if(line.empty()) continue;

        stringstream ss(line);
        string ip, port,synp;


        getline(ss, ip, ':');
        getline(ss, port,':');
        getline(ss,synp);

        if(!ip.empty() && !port.empty()) {
            ipadd.push_back(ip);
            ports.push_back(atoi(port.c_str()));
            ports.push_back(atoi(synp.c_str()));
        }
    }

    
    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd < 0){
        perror("socket creation is unsuccessful");
        exit(1);
    }

    int portno;
    string myip;
    int syn_list;
    int syn_send;

    if (tacknum == 1) {
        portno   = ports[0];   // client port for tracker1
        myip     = ipadd[0];
        syn_list = ports[1];   // tracker1’s own sync port
        syn_send = ports[3];   // connect to tracker2’s sync port
    } else {
        portno   = ports[2];   // client port for tracker2
        myip     = ipadd[1];
        syn_list = ports[3];   // tracker2’s own sync port
        syn_send = ports[1];   // connect to tracker1’s sync port
    }

    // start listener on my sync port
    thread listener_thread(syn_listener, syn_list, myip);
    listener_thread.detach();

    // start sender to peer’s sync port
    thread sender_thread(syn_sender, syn_send, ipadd[(tacknum == 1) ? 1: 0]);
    sender_thread.detach();



    struct sockaddr_in sadr;
    bzero((char*)&sadr, sizeof(sadr));
    sadr.sin_family = AF_INET;
    sadr.sin_addr.s_addr = inet_addr(myip.c_str());
    sadr.sin_port = htons(portno);

    if(bind(sockfd, (struct sockaddr*)&sadr,sizeof(sadr)) < 0){
        perror("cant bind client socket");
        exit(1);
    }

    listen(sockfd,5);

    printf("Tracker listening for clients on port %d\n", portno);

    // Accept multiple clients
    while(1){
        struct sockaddr_in cadr;
        socklen_t clientlen = sizeof(cadr);
        int newsfd = accept(sockfd, (struct sockaddr*)&cadr,&clientlen);
        if(newsfd < 0){
            perror("Error on accept client");
            continue;
        }

        {
            lock_guard<mutex> lock(clients_mutex);
            clients.push_back(newsfd);
        }

        thread t(handlepeers, newsfd);
        t.detach();
    }

    close(sockfd);
    return 0;
}
