
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <netdb.h>
#include <sstream>
#include <algorithm>
#include <vector>
#include <fcntl.h>
#include <openssl/sha.h>
#include <iomanip>
#include <fstream>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <random>


using namespace std;

int g_listen_port = 0;
string currentUser = ""; 

struct DownloadInfo {
    string filename;
    string group;
    long filesize;
    int totalPieces;
    atomic<int> piecesDownloaded;
    vector<bool> pieceDone;
    mutex mtx;
};

unordered_map<string, shared_ptr<DownloadInfo>> activeDownloads; // filename -> DownloadInfo
unordered_map<string, string> completedDownloads; // filename -> group
mutex downloadsMutex;
unordered_map<int, unordered_set<string>> pieceFailedPeers;

unordered_map<string, string> localFiles;  // filename -> fullpath
mutex localFilesMutex;
mutex coutMutex; 

const size_t PIECE_SIZE = 512 * 1024; // 512 KB

void error(const char* msg){
    cerr << msg << endl;
    exit(0);
}

// helper to split string
vector<string> split(const string &s, char delimiter) {
    vector<string> tokens;
    string token;
    stringstream ss(s);
    while (getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

bool fetchPiece(const string& ip, int port, const string& filename,
                int piece_index, vector<char>& out, size_t pieceSize) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if(inet_pton(AF_INET, ip.c_str(), &addr.sin_addr)<=0){ close(sockfd); return false; }

    if(connect(sockfd, (struct sockaddr*)&addr, sizeof(addr))<0){ close(sockfd); return false; }

    string req = "GET_PIECE|" + filename + "|" + to_string(piece_index) + "\n";
    send(sockfd, req.c_str(), req.size(), 0);

    vector<char> buffer(pieceSize);
    int totalRead = 0;
    while(totalRead < (int)pieceSize){
        int n = recv(sockfd, buffer.data()+totalRead, pieceSize-totalRead, 0);
        if(n <= 0) break;
        totalRead += n;
    }

    if(totalRead == 0){ close(sockfd); return false; }

    out.assign(buffer.begin(), buffer.begin()+totalRead);
    close(sockfd);
    return true;
}

bool is_safe_path(const string &p) {
    if (p.find("..") != string::npos) return false;
    return true;
}


void handleShowDownloads() {
    lock_guard<mutex> lock(downloadsMutex);

    if(activeDownloads.empty() && completedDownloads.empty()) {
        cout << "[Client] No downloads.\n";
        return;
    }

    
    for(auto &entry : activeDownloads) {
        auto &d = entry.second;
        int done = d->piecesDownloaded.load();
        int total = d->totalPieces;
        double percent = (total>0) ? (done*100.0/total) : 0;

        int barWidth = 20;
        int pos = static_cast<int>(barWidth * percent / 100.0);
        string bar = "[";
        for(int i=0;i<barWidth;i++){
            if(i<pos) bar += "=";
            else if(i==pos) bar += ">";
            else bar += " ";
        }
        bar += "]";

        cout << "[O] " << d->group << " " << d->filename
             << " | " << done << "/" << total
             << " pieces | " << fixed << setprecision(2) << percent << "% "
             << bar << endl;
    }

    
    for(auto &entry : completedDownloads) {
        cout << "[C] " << entry.second << " " << entry.first << endl;
    }
}


void handleStopShare(vector<string> &tokens, int tracker_fd) {
    if(tokens.size() < 3){
        cout << "Usage: stop_share <group_id> <file_name>\n";
        return;
    }

    if(currentUser.empty()){
        cout << "[Client] Please login first to stop sharing.\n";
        return;
    }

    string group = tokens[1];
    string filename = tokens[2];

    {
        lock_guard<mutex> lock(localFilesMutex);
        auto it = localFiles.find(filename);
        if(it != localFiles.end()) localFiles.erase(it);
        else { cout << "[Client] You are not sharing file: " << filename << "\n"; return; }
    }

    string msg = "STOP_SHARE|" + group + "|" + filename + "|" + currentUser + "\n";
    send(tracker_fd, msg.c_str(), msg.size(), 0);

    cout << "[Client] Stopped sharing file: " << filename << " in group " << group << endl;
}


string handleUploadFile(vector<string>& tokens) {
    if(tokens.size() < 3){
        cout << "Usage: upload_file <group_id> <file_path>" << endl;
        return "";
    }

    if(currentUser.empty()){
        cout << "[Client] Please login first to upload.\n";
        return "";
    }

    string filepath = tokens[2];
    if(!is_safe_path(filepath)){
        cout << "[Client] Unsafe filepath\n";
        return "";
    }

    
    size_t pos = filepath.find_last_of("/\\");
    string filename = (pos == string::npos) ? filepath : filepath.substr(pos + 1);

    {
        lock_guard<mutex> lock(localFilesMutex);
        localFiles[filename] = filepath;
    }

    ifstream infile(filepath, ios::binary);
    if(!infile.is_open()){
        cerr << "[ERROR] Cannot open file: " << filepath << endl;
        return "";
    }

    infile.seekg(0, ios::end);
    long filesize = infile.tellg();
    infile.seekg(0, ios::beg);

    vector<char> buffer(PIECE_SIZE);
    vector<string> pieceHashes;

    while(true) {
        infile.read(buffer.data(), PIECE_SIZE);
        streamsize bytesRead = infile.gcount();
        if(bytesRead <= 0) break;

        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(buffer.data()), bytesRead, hash);

        stringstream ss;
        for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
            ss << hex << setw(2) << setfill('0') << (int)hash[i];

        pieceHashes.push_back(ss.str());
    }
    infile.close();

    string allHashes;
    for(size_t i = 0; i < pieceHashes.size(); i++) {
        allHashes += pieceHashes[i];
        if(i < pieceHashes.size() - 1) allHashes += ",";
    }

    string msg = "UPLOAD_FILE|" + tokens[1] + "|" + filename + "|" +
                 to_string(filesize) + "|" + allHashes + "|" +
                 to_string(g_listen_port) + "\n";

    cout << "[Client] File prepared for upload. Pieces: " << pieceHashes.size() << endl;
    return msg;
}




void handleDownloadFile(vector<string>& tokens, int tracker_fd) {
    if(tokens.size() < 3) {
        cout << "Usage: download_file <group_id> <filename> [destination_path]\n";
        return;
    }

    if(!is_safe_path(tokens[2])) {
        cout << "[Client] Unsafe filename\n";
        return;
    }

    string group = tokens[1];
    string filename = tokens[2];
    string destPath = (tokens.size() >= 4) ? tokens[3] : filename;
    if(destPath.back() == '/' || destPath.back() == '\\') destPath += filename;

    
    
    string req = "DOWNLOAD_FILE|" + group + "|" + filename + "\n";
    send(tracker_fd, req.c_str(), req.size(), 0);

    char buffer[8192];
    int n = recv(tracker_fd, buffer, sizeof(buffer) - 1, 0);
    if(n <= 0) { cout << "[Client] Tracker disconnected.\n"; return; }
    buffer[n] = '\0';
    string response(buffer);

    auto respTokens = split(response, '|');
    if(respTokens.size() < 5 || respTokens[0] != "OK") {
        cout << "[Client] Download failed: " << response << endl;
        return;
    }

    long filesize = stol(respTokens[2]);
    vector<string> pieceHashes = split(respTokens[3], ',');
    vector<string> peers = split(respTokens[4], ',');
    int totalPieces = pieceHashes.size();

    auto downloadInfo = make_shared<DownloadInfo>();
    downloadInfo->filename = filename;
    downloadInfo->group = group;
    downloadInfo->filesize = filesize;
    downloadInfo->totalPieces = totalPieces;
    downloadInfo->piecesDownloaded = 0;
    downloadInfo->pieceDone = vector<bool>(totalPieces, false);

    {
        lock_guard<mutex> lock(downloadsMutex);
        activeDownloads[filename] = downloadInfo;
    }

    vector<vector<char>> pieceData(totalPieces);
    queue<int> workQueue;
    for(int i = 0; i < totalPieces; i++) workQueue.push(i);

    mutex queueMutex, coutMutex;
    unordered_map<int, unordered_set<string>> pieceFailedPeers;

    int numThreads = min(totalPieces, (int)max(1u, thread::hardware_concurrency()));
    vector<thread> threads;

    auto worker = [&]() {
        while(true) {
            int idx;
            {
                lock_guard<mutex> lock(queueMutex);
                if(workQueue.empty()) return;
                idx = workQueue.front();
                workQueue.pop();
            }

            bool success = false;

            // Build available peers for this piece
            vector<string> availablePeers;
            for(const auto& peer : peers){
                if(pieceFailedPeers[idx].find(peer) == pieceFailedPeers[idx].end())
                    availablePeers.push_back(peer);
            }

            if(availablePeers.empty()){
                // All peers failed → reset failed set & retry
                pieceFailedPeers[idx].clear();
                availablePeers = peers;
                this_thread::sleep_for(chrono::milliseconds(100)); // small backoff
            }

            // Shuffle available peers
            std::random_device rd;
            std::mt19937 g(rd());
            std::shuffle(availablePeers.begin(), availablePeers.end(), g);

            for(const auto& peer : availablePeers){
                size_t atPos = peer.find('@');
                if(atPos == string::npos) continue;

                string ipPort = peer.substr(atPos + 1);
                size_t colonPos = ipPort.find(':');
                if(colonPos == string::npos) continue;

                string ip = ipPort.substr(0, colonPos);
                int port = stoi(ipPort.substr(colonPos + 1));

                size_t pieceSize = PIECE_SIZE;
                if(idx == totalPieces - 1) pieceSize = filesize - PIECE_SIZE * idx;

                vector<char> buffer;
                if(fetchPiece(ip, port, filename, idx, buffer, pieceSize)) {
                    unsigned char hash[SHA_DIGEST_LENGTH];
                    SHA1(reinterpret_cast<const unsigned char*>(buffer.data()), buffer.size(), hash);
                    stringstream ss;
                    for(int k = 0; k < SHA_DIGEST_LENGTH; k++)
                        ss << hex << setw(2) << setfill('0') << (int)hash[k];

                    if(ss.str() == pieceHashes[idx]) {
                        pieceData[idx] = buffer;
                        downloadInfo->pieceDone[idx] = true;
                        downloadInfo->piecesDownloaded++;

                        lock_guard<mutex> lock(coutMutex);
                        cout << "[Client] Piece " << idx << "/" << totalPieces-1
                             << " downloaded (" << downloadInfo->piecesDownloaded << "/" << totalPieces << ")\n";
                        success = true;
                        break;
                    }
                }

                // mark peer as failed for this piece
                pieceFailedPeers[idx].insert(peer);
            }

            if(!success){
                lock_guard<mutex> lock(queueMutex);
                workQueue.push(idx); // retry later
                this_thread::sleep_for(chrono::milliseconds(100)); // backoff
            }
        }
    };

    // Launch threads
    for(int i = 0; i < numThreads; i++) threads.emplace_back(worker);
    for(auto &t : threads) t.join();

    // Check completion
    bool allDone = all_of(downloadInfo->pieceDone.begin(), downloadInfo->pieceDone.end(),
                          [](bool done){ return done; });
    if(!allDone) {
        cerr << "[Client] Download incomplete.\n";
        lock_guard<mutex> lock(downloadsMutex);
        activeDownloads.erase(filename);
        return;
    }

    // Write file
    ofstream outfile(destPath, ios::binary);
    for(int i = 0; i < totalPieces; i++) outfile.write(pieceData[i].data(), pieceData[i].size());
    outfile.close();

    {
        lock_guard<mutex> lock(downloadsMutex);
        activeDownloads.erase(filename);
        completedDownloads[filename] = group;
    }

    {
        lock_guard<mutex> lock(localFilesMutex);
        localFiles[filename] = destPath;
    }

    // Register as seeder
    char hostname[256];
    if(gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent *h = gethostbyname(hostname);
        if(h && h->h_addr_list && h->h_addr_list[0]) {
            char ipbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, h->h_addr_list[0], ipbuf, sizeof(ipbuf));
            string myip = string(ipbuf);
            string newSeederMsg = "NEW_SEEDER|" + group + "|" + filename + "|" + currentUser + "|" + myip + ":" + to_string(g_listen_port) + "\n";
            send(tracker_fd, newSeederMsg.c_str(), newSeederMsg.size(), 0);
        }
    }

    // Mark complete
    string completeMsg = "DOWNLOAD_COMPLETE|DOWNLOAD_COMPLETE|" + group + "|" + filename + "|" + currentUser + "\n";
    send(tracker_fd, completeMsg.c_str(), completeMsg.size(), 0);

    cout << "[C] " << group << " " << filename << endl;
    cout << "[Client] File downloaded successfully to " << destPath << " and registered as seeder.\n";
}


void peerServer(int listen_port){
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0){ perror("socket"); exit(1); }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);

    if(bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0){ perror("bind"); exit(1); }
    if(listen(server_fd, 5) < 0){ perror("listen"); exit(1); }

    cout << "[Peer Server] Listening on port " << listen_port << endl;

    while(true){
        sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);
        if(client_fd < 0){ perror("accept"); continue; }

        thread([client_fd](){
            char buffer[1024];
            int n = recv(client_fd, buffer, sizeof(buffer), 0);
            if(n <= 0){ close(client_fd); return; }

            string req(buffer, n);
            auto tokens = split(req, '|');
            if(tokens.size() < 3){ close(client_fd); return; }

            string filename = tokens[1];
            int piece_index = stoi(tokens[2]);

            string fullpath;
            {
                lock_guard<mutex> lock(localFilesMutex);
                if(localFiles.find(filename) == localFiles.end()){ close(client_fd); return; }
                fullpath = localFiles[filename];
            }

            ifstream file(fullpath, ios::binary);
            if(!file.is_open()){ close(client_fd); return; }

            file.seekg(piece_index*PIECE_SIZE);
            vector<char> data(PIECE_SIZE);
            file.read(data.data(), PIECE_SIZE);
            int bytesRead = file.gcount();

            int totalSent = 0;
            while(totalSent < bytesRead){
                int sent = send(client_fd, data.data()+totalSent, bytesRead-totalSent, 0);
                if(sent <= 0) break;
                totalSent += sent;
            }
            close(client_fd);
        }).detach();
    }
}

// Command handling
vector<string> handleCommands(string msg){
    vector<string> tokens;
    stringstream ss(msg);
    string token;
    while(ss >> token) tokens.push_back(token);
    return tokens;
}

string buildProtocol(vector<string> &tokens){
    if(tokens.empty()) return "";
    string cmd = tokens[0];
    transform(cmd.begin(), cmd.end(), cmd.begin(), ::toupper);
    string result = cmd;
    for(size_t i=1;i<tokens.size();i++) result += "|" + tokens[i];
    result += "\n";
    return result;
}

// Main
int main(int argc , char* argv[]){
    srand(time(NULL));
    g_listen_port = 10000 + rand() % 10000;
    thread(peerServer, g_listen_port).detach();

    if(argc < 3){ perror("Usage: ./client <IP:PORT> tracker_info.txt\n"); exit(1); }

    string arg1 = argv[1];
    size_t pos = arg1.find(':');
    if(pos == string::npos){ perror("Invalid <IP:PORT> format\n"); exit(1); }
    string primary_ip = arg1.substr(0, pos);
    int primary_port = stoi(arg1.substr(pos+1));

    const char* file = argv[2];
    int fd = open(file,O_RDONLY);
    if(fd<0){ perror("Cant open tracker_info file"); exit(1); }

    char buffer[4096];
    int bytes = read(fd, buffer, sizeof(buffer)-1);
    buffer[bytes] = '\0';
    close(fd);
    string fileContent(buffer);
    stringstream fileStream(fileContent);
    string line;
    vector<string> ipadd; vector<int> ports;
    while(getline(fileStream,line)){
        if(line.empty()) continue;
        stringstream ss(line);
        string ip, port;
        getline(ss, ip, ':'); getline(ss, port);
        if(!ip.empty() && !port.empty()){ ipadd.push_back(ip); ports.push_back(atoi(port.c_str())); }
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0){ perror("Socket creation failed"); exit(1); }

    struct sockaddr_in sadd1{};
    sadd1.sin_family = AF_INET;
    sadd1.sin_port = htons(primary_port);
    if(inet_pton(AF_INET, primary_ip.c_str(), &sadd1.sin_addr) <= 0){ perror("Invalid primary IP address"); exit(1); }

    if(connect(sockfd, (struct sockaddr*)&sadd1, sizeof(sadd1)) < 0){
        close(sockfd); bool connected = false;
        for(size_t i = 0; i < ipadd.size(); i++){
            if(ipadd[i] == primary_ip && ports[i] == primary_port) continue;
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if(sockfd < 0){ perror("Socket creation failed"); exit(1); }
            struct sockaddr_in sadd2{};
            sadd2.sin_family = AF_INET; sadd2.sin_port = htons(ports[i]);
            if(inet_pton(AF_INET, ipadd[i].c_str(), &sadd2.sin_addr) <= 0) continue;
            if(connect(sockfd, (struct sockaddr*)&sadd2, sizeof(sadd2)) == 0){
                printf("Connected to backup tracker %s:%d\n", ipadd[i].c_str(), ports[i]);
                connected = true; break;
            }
            close(sockfd);
        }
        if(!connected){ perror("Unable to connect to any tracker"); exit(1); }
    } else printf("Connected to primary tracker %s:%d\n", primary_ip.c_str(), primary_port);

    char buff[4096];
    while(true){
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        int maxfd = max(sockfd, STDIN_FILENO) + 1;

        int activity = select(maxfd, &readfds, NULL, NULL, NULL);
        if(activity < 0){ perror("select error"); exit(1); }

        if(FD_ISSET(sockfd, &readfds)){
            int n = recv(sockfd, buff, sizeof(buff)-1,0);
            if(n <= 0){ printf("Server disconnected.\n"); exit(0); }
            buff[n] = '\0';
            string serverReply(buff);

            if(serverReply.rfind("OK|Login success for ", 0) == 0) {
                string rest = serverReply.substr(strlen("OK|Login success for "));
                rest.erase(remove(rest.begin(), rest.end(), '\n'), rest.end());
                rest.erase(remove(rest.begin(), rest.end(), '\r'), rest.end());
                currentUser = rest;
                cout << "\n[Server Reply] " << serverReply << endl;
                cout << "You: "; fflush(stdout);
                continue;
            }

            printf("\n[Server Reply] %s\n", buff);
            printf("You: "); fflush(stdout);
        }

        if(FD_ISSET(STDIN_FILENO, &readfds)){
            bzero(buff, sizeof(buff));
            if(!fgets(buff, sizeof(buff), stdin)) break;
            string msg(buff);
            msg.erase(remove(msg.begin(), msg.end(), '\n'), msg.end());

            stringstream multi(msg);
            string part;
            while(getline(multi, part, ';')){
                part.erase(0, part.find_first_not_of(" \t"));
                part.erase(part.find_last_not_of(" \t")+1);
                if(part.empty()) continue;

                vector<string> tokens = handleCommands(part);
                if(tokens.empty()) continue;
                string cmdLower = tokens[0];
                transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::tolower);

                if(cmdLower == "exit" || cmdLower == "quit") { close(sockfd); return 0; }
               else if(cmdLower == "upload_file") {
    string protocolMsg = handleUploadFile(tokens);
    if(!protocolMsg.empty()) {

        const size_t CHUNK_SIZE = 4096;
        size_t sent = 0;
        while(sent < protocolMsg.size()) {
            size_t toSend = min(CHUNK_SIZE, protocolMsg.size() - sent);
            send(sockfd, protocolMsg.c_str() + sent, toSend, 0);
            sent += toSend;
        }
    }
}

                else if(cmdLower == "show_downloads") handleShowDownloads();
                else if(cmdLower == "stop_share") handleStopShare(tokens, sockfd);
                else if(cmdLower == "download_file") handleDownloadFile(tokens, sockfd);
                else {
                    string protocolMsg = buildProtocol(tokens);
                    if(!protocolMsg.empty()) send(sockfd, protocolMsg.c_str(), protocolMsg.size(), 0);
                }
            }
        }
    }

    close(sockfd);
    return 0;
}
