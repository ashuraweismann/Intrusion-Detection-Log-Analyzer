#ifndef LOGLIST_H
#define LOGLIST_H

#include "LogNode.h"
#include <iostream>
using namespace std;

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
    void deleteOldLogs(long currentTime, long expirySeconds);
    void clear();

    //Attack Detection
    void detectBruteForce(int threshold);
    void detectPortScan(int portThreshold);
    void detectSuspiciousActivity(int requestThreshold);

    //Load log file
    void loadFromFile(const string& filename);


};

#endif
