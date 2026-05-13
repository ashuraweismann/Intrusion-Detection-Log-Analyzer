#ifndef CUSTOMQUEUE_H
#define CUSTOMQUEUE_H

#include <cstddef>

template <typename T>
class CustomQueue {
private:
    struct QueueNode {
        T data;
        QueueNode* next;

        explicit QueueNode(const T& value)
            : data(value), next(nullptr) {
        }
    };

    QueueNode* frontNode;
    QueueNode* rearNode;
    int itemCount;

public:
    CustomQueue()
        : frontNode(nullptr), rearNode(nullptr), itemCount(0) {
    }

    ~CustomQueue() {
        clear();
    }

    CustomQueue(const CustomQueue&) = delete;
    CustomQueue& operator=(const CustomQueue&) = delete;

    void push(const T& value) {
        QueueNode* newNode = new QueueNode(value);

        if (rearNode == nullptr) {
            frontNode = newNode;
            rearNode = newNode;
        } else {
            rearNode->next = newNode;
            rearNode = newNode;
        }

        itemCount++;
    }

    void pop() {
        if (frontNode == nullptr) {
            return;
        }

        QueueNode* oldFront = frontNode;
        frontNode = frontNode->next;

        if (frontNode == nullptr) {
            rearNode = nullptr;
        }

        delete oldFront;
        itemCount--;
    }

    T& front() {
        return frontNode->data;
    }

    const T& front() const {
        return frontNode->data;
    }

    bool empty() const {
        return frontNode == nullptr;
    }

    int size() const {
        return itemCount;
    }

    void clear() {
        while (!empty()) {
            pop();
        }
    }
};

#endif
