#include "../include/packet_analyzer.h"
#include <iostream>
#include <csignal>

using namespace std;

PacketAnalyzer* globalAnalyzer = nullptr;

void signalHandler(int signum) {
    if (globalAnalyzer) {
        globalAnalyzer->stopCapture();
    }
}

int main() {
    PacketAnalyzer analyzer;
    globalAnalyzer = &analyzer;

    // Register signal handler for graceful shutdown
    signal(SIGINT, signalHandler);

    if (!analyzer.initialize("en0")) {  // Replace "en0" with your actual interface name
        cerr << "Failed to initialize packet analyzer" << endl;
        return 1;
    }

    cout << "Starting packet capture... Press Ctrl+C to stop." << endl;
    analyzer.startCapture();

    // Print final statistics
    const auto& stats = analyzer.getGlobalStats();
    cout << "\nCapture completed. Statistics:" << endl;
    cout << "Total packets: " << stats.totalPackets << endl;
    cout << "Packets per second: " << stats.packetsPerSecond << endl;
    
    for (const auto& [protocol, count] : stats.protocolCount) {
        cout << protocol << " packets: " << count << endl;
    }

    return 0;
} 