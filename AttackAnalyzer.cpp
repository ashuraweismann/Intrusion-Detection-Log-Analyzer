#include "AttackAnalyzer.h"
#include "CustomHashTable.h"

using namespace std;

vector<string> AttackAnalyzer::findPortScans(const vector<LogRecord>& records, int portThreshold) {
    IPStatsHashTable ipStats;

    for (const LogRecord& record : records) {
        ipStats.addPort(record.srcIP, record.dstPort);
    }

    vector<string> alerts;
    for (const IPStatsRecord& record : ipStats.getRecords()) {
        if (record.uniquePortCount >= portThreshold) {
            alerts.push_back(
                "IP: " + record.ip +
                " | Unique Ports Scanned: " + to_string(record.uniquePortCount)
            );
        }
    }

    return alerts;
}

vector<string> AttackAnalyzer::findSuspiciousActivity(const vector<LogRecord>& records, int requestThreshold) {
    IPStatsHashTable ipStats;

    for (const LogRecord& record : records) {
        ipStats.addRequest(record.srcIP, record.attemptCount);
    }

    vector<string> alerts;
    for (const IPStatsRecord& record : ipStats.getRecords()) {
        if (record.totalRequests >= requestThreshold) {
            alerts.push_back(
                "IP: " + record.ip +
                " | Total Requests: " + to_string(record.totalRequests)
            );
        }
    }

    return alerts;
}
