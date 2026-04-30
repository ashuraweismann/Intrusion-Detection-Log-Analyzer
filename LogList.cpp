#include "LogList.h"
#include <ctime>
#include <fstream>
#include <sstream>

namespace {
const char* RED = "\033[31m";
const char* YELLOW = "\033[33m";
const char* MAGENTA = "\033[35m";
}

void LogList::insertLog(string ip, int port, int count, string type, long time) {
    LogNode* newNode = new LogNode(ip, port, count, type, time);

    newNode->next = head;   // point to old first node
    head = newNode;         // update head
}

void LogList::displayLogs() {
    if (head == nullptr) {
        cout << "No logs available.\n";
        return;
    }

    LogNode* temp = head;
    while (temp != nullptr) {
        cout << "IP: " << temp->srcIP
             << " | Port: " << temp->dstPort
             << " | Attempts: " << temp->attemptCount
             << " | Type: " << temp->attackType
             << " | Time: " << temp->timestamp
             << endl;
        temp = temp->next;
    }
}

void LogList::deleteLogsInRange(long startTime, long endTime) {
    if (startTime > endTime) {
        long tempTime = startTime;
        startTime = endTime;
        endTime = tempTime;
    }

    // Delete from beginning if needed
    while (head != nullptr &&
           head->timestamp >= startTime &&
           head->timestamp <= endTime) {
        LogNode* temp = head;
        head = head->next;
        delete temp;
    }

    if (head == nullptr) return;

    // Delete in middle or end
    LogNode* curr = head;
    while (curr->next != nullptr) {
        if (curr->next->timestamp >= startTime &&
            curr->next->timestamp <= endTime) {
            LogNode* temp = curr->next;
            curr->next = temp->next;
            delete temp;
        } else {
            curr = curr->next;
        }
    }
}

void LogList::clear() {
    while (head != nullptr) {
        LogNode* temp = head;
        head = head->next;
        delete temp;
    }
}


//1. Brute Force Detection

void LogList::detectBruteForce(int threshold) {
    LogNode* temp = head;
    bool found = false;

    while (temp != nullptr) {
        if (temp->attemptCount >= threshold &&
            temp->attackType == "FAILED_LOGIN") {
            found = true;

            cout << RED << "[ALERT] Brute Force Attack Detected!\n";
            cout << "IP: " << temp->srcIP
                 << " | Port: " << temp->dstPort
                 << " | Attempts: " << temp->attemptCount << "\n\n"
                 << MAGENTA;
        }
        temp = temp->next;
    }

    if (!found) {
        cout << YELLOW
             << "[INFO] No brute force activity detected for threshold: "
             << threshold << "\n"
             << MAGENTA;
    }
}


//2. Port Scan Detection

void LogList::detectPortScan(int portThreshold) {
    LogNode* outer = head;
    bool found = false;

    while (outer != nullptr) {
        int uniquePorts = 0;
        LogNode* inner = head;

        while (inner != nullptr) {
            if (inner->srcIP == outer->srcIP &&
                inner->dstPort != outer->dstPort) {
                uniquePorts++;
            }
            inner = inner->next;
        }

        if (uniquePorts >= portThreshold) {
            found = true;
            cout << RED << "[ALERT] Port Scan Detected!\n";
            cout << "IP: " << outer->srcIP
                 << " | Unique Ports Scanned: "
                 << uniquePorts + 1 << "\n\n"
                 << MAGENTA;
        }

        outer = outer->next;
    }

    if (!found) {
        cout << YELLOW
             << "[INFO] No port scan activity detected for threshold: "
             << portThreshold << "\n"
             << MAGENTA;
    }
}


//3. Suspicious Activity Detection

void LogList::detectSuspiciousActivity(int requestThreshold) {
    LogNode* outer = head;
    bool found = false;

    while (outer != nullptr) {
        bool alreadyProcessed = false;
        LogNode* previous = head;
        while (previous != outer) {
            if (previous->srcIP == outer->srcIP) {
                alreadyProcessed = true;
                break;
            }
            previous = previous->next;
        }

        if (alreadyProcessed) {
            outer = outer->next;
            continue;
        }

        int totalRequests = 0;
        LogNode* inner = head;

        while (inner != nullptr) {
            if (inner->srcIP == outer->srcIP) {
                totalRequests += inner->attemptCount;
            }
            inner = inner->next;
        }

        if (totalRequests >= requestThreshold) {
            found = true;
            cout << RED << "[ALERT] Suspicious Activity Detected!\n";
            cout << "IP: " << outer->srcIP
                 << " | Total Requests: " << totalRequests << "\n\n"
                 << MAGENTA;
        }

        outer = outer->next;
    }

    if (!found) {
        cout << YELLOW
             << "[INFO] No suspicious activity detected for threshold: "
             << requestThreshold << "\n"
             << MAGENTA;
    }
}
void LogList::loadFromFile(const string& filename) {
    ifstream file(filename);
    if (!file) {
        cout << "Error: Unable to open log file.\n";
        return;
    }

    string line;
    while (getline(file, line)) {
        if (line.empty()) {
            continue;
        }

        istringstream iss(line);
        string ip, type;
        int port, count;
        long timestamp;

        if (!(iss >> ip >> port >> count >> type)) {
            continue;
        }

        if (!(iss >> timestamp)) {
            timestamp = time(NULL);
        }

        insertLog(ip, port, count, type, timestamp);
    }

    file.close();
    cout << "Logs loaded successfully.\n";
}
