#ifndef LOGNODE_H
#define LOGNODE_H

#include <string>
using namespace std;

struct LogNode {
    string srcIP;          // Source IP address
    int dstPort;           // Destination port
    int attemptCount;      // Number of attempts
    string attackType;     // Attack category
    long timestamp;        // Time of event

    LogNode* next;         // Pointer to next log entry

    // Constructor
    LogNode(string ip, int port, int count, string type, long time) {
        srcIP = ip;
        dstPort = port;
        attemptCount = count;
        attackType = type;
        timestamp = time;
        next = nullptr;
    }
};

#endif
