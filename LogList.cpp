#include "LogList.h"

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

void LogList::deleteOldLogs(long currentTime, long expirySeconds) {
    // Delete from beginning if needed
    while (head != nullptr && (currentTime - head->timestamp) > expirySeconds) {
        LogNode* temp = head;
        head = head->next;
        delete temp;
    }

    if (head == nullptr) return;

    // Delete in middle or end
    LogNode* curr = head;
    while (curr->next != nullptr) {
        if ((currentTime - curr->next->timestamp) > expirySeconds) {
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

    while (temp != nullptr) {
        if (temp->attemptCount >= threshold &&
            temp->attackType == "FAILED_LOGIN") {

            cout << "[ALERT] Brute Force Attack Detected!\n";
            cout << "IP: " << temp->srcIP
                 << " | Port: " << temp->dstPort
                 << " | Attempts: " << temp->attemptCount << "\n\n";
        }
        temp = temp->next;
    }
}


//2. Port Scan Detection

void LogList::detectPortScan(int portThreshold) {
    LogNode* outer = head;

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
            cout << "[ALERT] Port Scan Detected!\n";
            cout << "IP: " << outer->srcIP
                 << " | Unique Ports Scanned: "
                 << uniquePorts + 1 << "\n\n";
        }

        outer = outer->next;
    }
}


//3. Suspicious Activity Detection

void LogList::detectSuspiciousActivity(int requestThreshold) {
    LogNode* outer = head;

    while (outer != nullptr) {
        int count = 0;
        LogNode* inner = head;

        while (inner != nullptr) {
            if (inner->srcIP == outer->srcIP) {
                count++;
            }
            inner = inner->next;
        }

        if (count >= requestThreshold) {
            cout << "[ALERT] Suspicious Activity Detected!\n";
            cout << "IP: " << outer->srcIP
                 << " | Total Requests: " << count << "\n\n";
        }

        outer = outer->next;
    }
}


//log file loader

#include <fstream>
#include <ctime>

void LogList::loadFromFile(const string& filename) {
    ifstream file(filename);
    if (!file) {
        cout << "Error: Unable to open log file.\n";
        return;
    }

    string ip, type;
    int port, count;

    while (file >> ip >> port >> count >> type) {
        long currentTime = time(NULL);
        insertLog(ip, port, count, type, currentTime);
    }

    file.close();
    cout << "Logs loaded successfully.\n";
}


