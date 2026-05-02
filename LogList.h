#ifndef LOGLIST_H
#define LOGLIST_H

#include "LogNode.h"
#include <iostream>
#include <vector>
using namespace std;

struct LogRecord {
    string srcIP;
    int dstPort;
    int attemptCount;
    string attackType;
    long timestamp;
};

class LogList {
private:
    LogNode* head;

public:
    LogList() {
        head = nullptr;
    }

    ~LogList() {
        clear();
    }

    void insertLog(string ip, int port, int count, string type, long time);
    void displayLogs();
    void deleteLogsInRange(long startTime, long endTime);
    void clear();
    vector<LogRecord> getLogs() const;
    int size() const;

    //Attack Detection
    void detectBruteForce(int threshold);
    void detectPortScan(int portThreshold);
    void detectSuspiciousActivity(int requestThreshold);

    //Load log file
    void loadFromFile(const string& filename);


};

#endif
