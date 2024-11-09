#include "../include/packet_analyzer.h"
#include <iostream>
#include <sqlite3.h>
#include <chrono>
#include <thread>

using namespace std;

bool ConnectionKey::operator<(const ConnectionKey& other) const {
    if (sourceIP != other.sourceIP) return sourceIP < other.sourceIP;
    if (destIP != other.destIP) return destIP < other.destIP;
    if (sourcePort != other.sourcePort) return sourcePort < other.sourcePort;
    if (destPort != other.destPort) return destPort < other.destPort;
    return protocol < other.protocol;
}

PacketAnalyzer::PacketAnalyzer() {}

PacketAnalyzer::~PacketAnalyzer() {
    if (handle) {
        pcap_close(handle);
    }
}

bool PacketAnalyzer::initialize(const string& interface) {
    // Check if interface exists
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return false;
    }
    
    bool interfaceFound = false;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        if (interface == d->name) {
            interfaceFound = true;
            break;
        }
    }
    pcap_freealldevs(alldevs);
    
    if (!interfaceFound) {
        cerr << "Interface " << interface << " not found" << endl;
        return false;
    }

    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return false;
    }

    // Set filter to capture IP packets
    struct bpf_program fp;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter" << std::endl;
        return false;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter" << std::endl;
        return false;
    }

    return true;
}

void PacketAnalyzer::startCapture() {
    isRunning = true;
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
}

void PacketAnalyzer::stopCapture() {
    isRunning = false;
    pcap_breakloop(handle);
}

void PacketAnalyzer::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto analyzer = reinterpret_cast<PacketAnalyzer*>(userData);
    analyzer->processPacket(pkthdr, packet);
}

void PacketAnalyzer::processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ip* ipHeader = (struct ip*)(packet + 14); // Skip Ethernet header
    
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

    ConnectionKey connection;
    connection.sourceIP = sourceIP;
    connection.destIP = destIP;

    // Determine protocol
    switch (ipHeader->ip_p) {
        case IPPROTO_TCP: {
            struct tcphdr* tcpHeader = (struct tcphdr*)(packet + 14 + ipHeader->ip_hl * 4);
            connection.sourcePort = ntohs(tcpHeader->th_sport);
            connection.destPort = ntohs(tcpHeader->th_dport);
            connection.protocol = "TCP";
            
            // Add application layer protocol detection
            switch(connection.destPort) {
                case 80:
                case 8080:
                    connection.protocol = "HTTP";
                    break;
                case 443:
                    connection.protocol = "HTTPS";
                    break;
                case 53:
                    connection.protocol = "DNS";
                    break;
                // Add more application protocols as needed
            }
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr* udpHeader = (struct udphdr*)(packet + 14 + ipHeader->ip_hl * 4);
            connection.sourcePort = ntohs(udpHeader->uh_sport);
            connection.destPort = ntohs(udpHeader->uh_dport);
            connection.protocol = "UDP";
            break;
        }
        default:
            connection.sourcePort = 0;
            connection.destPort = 0;
            connection.protocol = "OTHER";
    }

    updateMetrics(connection);
}

void PacketAnalyzer::updateMetrics(const ConnectionKey& connection) {
    lock_guard<mutex> lock(bufferMutex);
    packetBuffer.push_back(connection);
    
    if (packetBuffer.size() >= BUFFER_SIZE) {
        processBatch();
    }
}

void PacketAnalyzer::processBatch() {
    static auto lastUpdate = std::chrono::steady_clock::now();
    auto currentTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(currentTime - lastUpdate).count();
    
    // Update packets per second
    if (duration > 0) {
        globalStats.packetsPerSecond = static_cast<double>(packetBuffer.size()) / duration;
        lastUpdate = currentTime;
    }

    // Process packets in batch
    for (const auto& connection : packetBuffer) {
        globalStats.totalPackets++;
        globalStats.protocolCount[connection.protocol]++;
        auto& stats = connectionStats[connection];
        stats.totalPackets++;
        stats.protocolCount[connection.protocol]++;
    }
    
    saveToDatabase();
    packetBuffer.clear();
}

void PacketAnalyzer::saveToDatabase() {
    sqlite3* db;
    int rc = sqlite3_open("network_metrics.db", &db);
    
    if (rc) {
        cerr << "Can't open database: " << sqlite3_errmsg(db) << endl;
        return;
    }

    // Create tables if they don't exist
    const char* createTables = R"(
        CREATE TABLE IF NOT EXISTS global_stats (
            timestamp INTEGER,
            total_packets INTEGER,
            packets_per_second REAL
        );
        CREATE TABLE IF NOT EXISTS protocol_stats (
            timestamp INTEGER,
            protocol TEXT,
            count INTEGER
        );
        CREATE TABLE IF NOT EXISTS connection_stats (
            timestamp INTEGER,
            source_ip TEXT,
            dest_ip TEXT,
            source_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            packets INTEGER
        );
    )";

    char* errMsg = 0;
    rc = sqlite3_exec(db, createTables, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        cerr << "SQL error: " << errMsg << endl;
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return;
    }

    // Insert global stats
    time_t currentTime = time(nullptr);
    string insertGlobal = "INSERT INTO global_stats VALUES (" + 
                         to_string(currentTime) + ", " +
                         to_string(globalStats.totalPackets) + ", " +
                         to_string(globalStats.packetsPerSecond) + ");";
    
    rc = sqlite3_exec(db, insertGlobal.c_str(), 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        cerr << "SQL error: " << errMsg << endl;
        sqlite3_free(errMsg);
    }

    // Insert protocol stats
    for (const auto& [protocol, count] : globalStats.protocolCount) {
        string insertProtocol = "INSERT INTO protocol_stats VALUES (" +
                               to_string(currentTime) + ", '" +
                               protocol + "', " +
                               to_string(count) + ");";
        
        rc = sqlite3_exec(db, insertProtocol.c_str(), 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            cerr << "SQL error: " << errMsg << endl;
            sqlite3_free(errMsg);
        }
    }

    // Insert connection stats
    for (const auto& [key, stats] : connectionStats) {
        string insertConnection = "INSERT INTO connection_stats VALUES (" +
                                to_string(currentTime) + ", '" +
                                key.sourceIP + "', '" +
                                key.destIP + "', " +
                                to_string(key.sourcePort) + ", " +
                                to_string(key.destPort) + ", '" +
                                key.protocol + "', " +
                                to_string(stats.totalPackets) + ");";
        
        rc = sqlite3_exec(db, insertConnection.c_str(), 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            cerr << "SQL error: " << errMsg << endl;
            sqlite3_free(errMsg);
        }
    }

    sqlite3_close(db);
}

string PacketAnalyzer::performDNSLookup(const string& ipAddress) {
    struct sockaddr_in sa;
    char host[NI_MAXHOST];
    
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ipAddress.c_str(), &(sa.sin_addr));

    int result = getnameinfo(
        (struct sockaddr*)&sa, sizeof(sa),
        host, sizeof(host),
        nullptr, 0,
        NI_NAMEREQD
    );

    if (result != 0) {
        return ipAddress; // Return IP if lookup fails
    }

    return string(host);
} 