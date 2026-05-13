#include "AttackAnalyzer.h"

#include <unordered_map>
#include <unordered_set>

using namespace std;

vector<string> AttackAnalyzer::findPortScans(const vector<LogRecord>& records, int portThreshold) {
    unordered_map<string, unordered_set<int>> portsByIP;

    for (const LogRecord& record : records) {
        portsByIP[record.srcIP].insert(record.dstPort);
    }

    vector<string> alerts;
    for (const auto& entry : portsByIP) {
        if (static_cast<int>(entry.second.size()) >= portThreshold) {
            alerts.push_back(
                "IP: " + entry.first +
                " | Unique Ports Scanned: " + to_string(entry.second.size())
            );
        }
    }

    return alerts;
}

vector<string> AttackAnalyzer::findSuspiciousActivity(const vector<LogRecord>& records, int requestThreshold) {
    unordered_map<string, int> requestsByIP;

    for (const LogRecord& record : records) {
        requestsByIP[record.srcIP] += record.attemptCount;
    }

    vector<string> alerts;
    for (const auto& entry : requestsByIP) {
        if (entry.second >= requestThreshold) {
            alerts.push_back(
                "IP: " + entry.first +
                " | Total Requests: " + to_string(entry.second)
            );
        }
    }

    return alerts;
}
