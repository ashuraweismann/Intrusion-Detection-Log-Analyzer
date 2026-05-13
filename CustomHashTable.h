#ifndef CUSTOMHASHTABLE_H
#define CUSTOMHASHTABLE_H

#include <string>
#include <vector>

struct IPStatsRecord {
    std::string ip;
    int totalRequests;
    int uniquePortCount;
};

class IntHashSet {
private:
    struct SetNode {
        int value;
        SetNode* next;

        explicit SetNode(int newValue)
            : value(newValue), next(nullptr) {
        }
    };

    static const int BucketCount = 31;
    SetNode* buckets[BucketCount];
    int itemCount;

    int hash(int value) const {
        if (value < 0) {
            value = -value;
        }
        return value % BucketCount;
    }

public:
    IntHashSet()
        : itemCount(0) {
        for (int i = 0; i < BucketCount; ++i) {
            buckets[i] = nullptr;
        }
    }

    ~IntHashSet() {
        clear();
    }

    IntHashSet(const IntHashSet&) = delete;
    IntHashSet& operator=(const IntHashSet&) = delete;

    bool contains(int value) const {
        int index = hash(value);
        SetNode* current = buckets[index];

        while (current != nullptr) {
            if (current->value == value) {
                return true;
            }
            current = current->next;
        }

        return false;
    }

    void insert(int value) {
        if (contains(value)) {
            return;
        }

        int index = hash(value);
        SetNode* newNode = new SetNode(value);
        newNode->next = buckets[index];
        buckets[index] = newNode;
        itemCount++;
    }

    int size() const {
        return itemCount;
    }

    void clear() {
        for (int i = 0; i < BucketCount; ++i) {
            SetNode* current = buckets[i];
            while (current != nullptr) {
                SetNode* nextNode = current->next;
                delete current;
                current = nextNode;
            }
            buckets[i] = nullptr;
        }
        itemCount = 0;
    }
};

class IPStatsHashTable {
private:
    struct TableNode {
        std::string ip;
        int totalRequests;
        IntHashSet ports;
        TableNode* next;

        explicit TableNode(const std::string& newIP)
            : ip(newIP), totalRequests(0), next(nullptr) {
        }
    };

    static const int BucketCount = 101;
    TableNode* buckets[BucketCount];

    int hash(const std::string& key) const {
        unsigned long hashValue = 0;
        for (char character : key) {
            hashValue = (hashValue * 31) + static_cast<unsigned char>(character);
        }
        return static_cast<int>(hashValue % BucketCount);
    }

    TableNode* findNode(const std::string& ip) const {
        int index = hash(ip);
        TableNode* current = buckets[index];

        while (current != nullptr) {
            if (current->ip == ip) {
                return current;
            }
            current = current->next;
        }

        return nullptr;
    }

    TableNode* getOrCreateNode(const std::string& ip) {
        TableNode* existing = findNode(ip);
        if (existing != nullptr) {
            return existing;
        }

        int index = hash(ip);
        TableNode* newNode = new TableNode(ip);
        newNode->next = buckets[index];
        buckets[index] = newNode;
        return newNode;
    }

public:
    IPStatsHashTable() {
        for (int i = 0; i < BucketCount; ++i) {
            buckets[i] = nullptr;
        }
    }

    ~IPStatsHashTable() {
        clear();
    }

    IPStatsHashTable(const IPStatsHashTable&) = delete;
    IPStatsHashTable& operator=(const IPStatsHashTable&) = delete;

    void addRequest(const std::string& ip, int requestCount) {
        TableNode* node = getOrCreateNode(ip);
        node->totalRequests += requestCount;
    }

    void addPort(const std::string& ip, int port) {
        TableNode* node = getOrCreateNode(ip);
        node->ports.insert(port);
    }

    std::vector<IPStatsRecord> getRecords() const {
        std::vector<IPStatsRecord> records;

        for (int i = 0; i < BucketCount; ++i) {
            TableNode* current = buckets[i];
            while (current != nullptr) {
                records.push_back({
                    current->ip,
                    current->totalRequests,
                    current->ports.size()
                });
                current = current->next;
            }
        }

        return records;
    }

    void clear() {
        for (int i = 0; i < BucketCount; ++i) {
            TableNode* current = buckets[i];
            while (current != nullptr) {
                TableNode* nextNode = current->next;
                delete current;
                current = nextNode;
            }
            buckets[i] = nullptr;
        }
    }
};

#endif
