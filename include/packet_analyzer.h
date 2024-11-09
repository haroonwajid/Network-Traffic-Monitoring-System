#pragma once

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>

struct ConnectionKey {
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort;
    uint16_t destPort;
    std::string protocol;

    bool operator<(const ConnectionKey& other) const;
};

struct ConnectionStats {
    uint64_t totalPackets = 0;
    std::map<std::string, uint64_t> protocolCount;
};

struct GlobalStats {
    uint64_t totalPackets = 0;
    double packetsPerSecond = 0.0;
    std::map<std::string, uint64_t> protocolCount;
};

class PacketAnalyzer {
public:
    PacketAnalyzer();
    ~PacketAnalyzer();

    bool initialize(const std::string& interface);
    void startCapture();
    void stopCapture();
    const GlobalStats& getGlobalStats() const { return globalStats; }

private:
    static const size_t BUFFER_SIZE = 1000;
    
    pcap_t* handle = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    bool isRunning = false;
    
    std::vector<ConnectionKey> packetBuffer;
    std::mutex bufferMutex;
    
    GlobalStats globalStats;
    std::map<ConnectionKey, ConnectionStats> connectionStats;

    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void updateMetrics(const ConnectionKey& connection);
    void processBatch();
    void saveToDatabase();
    std::string performDNSLookup(const std::string& ipAddress);
}; 