# Shadow IDS - Intrusion Detection Log Analyzer

## Project Report

## 1. Introduction

Shadow IDS is a C++ intrusion detection and packet analysis project. The system reads security logs or packet capture files, analyzes suspicious network behavior, and displays results through both a console interface and a Qt-based graphical user interface.

The main purpose of the project is to demonstrate how data structures can be used in a practical cybersecurity application. The project uses a linked list for storing logs, a custom queue for real-time simulation, and hash tables for fast packet grouping and attack classification.

## 2. Problem Statement

Network administrators need a simple way to inspect log files and packet captures to identify suspicious activity such as brute force attacks, port scans, and abnormal request patterns.

Traditional log files can be difficult to inspect manually because they may contain many entries. This project solves that problem by loading logs or PCAP files, organizing the data using data structures, detecting suspicious patterns, and displaying results in an easy-to-understand interface.

## 3. Objectives

- Load and analyze intrusion detection logs.
- Load classic `.pcap` packet capture files directly in the GUI.
- Display packet details in a Wireshark-style table.
- Simulate real-time scanning by releasing logs or packets one by one.
- Detect brute force login attempts.
- Detect port scanning behavior.
- Detect suspicious activity based on request count.
- Demonstrate practical use of linked lists, queues, and hash tables.
- Provide a GUI for easier interaction and report exporting.

## 4. Technologies Used

- C++
- Qt Widgets for GUI development
- CMake for building the GUI project
- Classic PCAP file parsing
- Data structures:
  - Linked List
  - Custom Queue
  - Hash Tables

## 5. Main Project Files

| File | Purpose |
| --- | --- |
| `main.cpp` | Console-based menu system |
| `LogNode.h` | Defines one linked list node for a log record |
| `LogList.h` | Declares linked list operations and detection methods |
| `LogList.cpp` | Implements linked list operations and attack detection |
| `AttackAnalyzer.h` | Declares hash-table based attack analysis functions |
| `AttackAnalyzer.cpp` | Implements improved port scan and suspicious activity detection |
| `CustomQueue.h` | Implements a custom queue without using STL queue |
| `CustomHashTable.h` | Implements custom hash table and hash set structures |
| `gui/MainWindow.h` | Declares the Qt GUI window and GUI data members |
| `gui/MainWindow.cpp` | Implements GUI, PCAP loading, simulation, and replay |
| `gui/CMakeLists.txt` | GUI build configuration |
| `pcap_to_logs.py` | Helper script to convert PCAP files to log format |
| `generate_demo_pcap.py` | Generates sample PCAP files for testing |

## 6. System Features

## 6.1 Log File Loading

The system can load text-based logs. Each log contains:

```text
source_ip destination_port attempt_count attack_type timestamp
```

Example:

```text
192.168.1.50 22 20 FAILED_LOGIN 1714464000
```

Loaded logs are stored in a linked list using the `LogList` class.

## 6.2 Direct PCAP File Loading

The GUI can directly load classic `.pcap` files without first converting them into `logs.txt`.

When a PCAP file is loaded, the program reads packet headers and extracts useful packet information such as:

- Timestamp
- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- Packet length
- TCP flag information

The packets are displayed in a table similar to Wireshark.

## 6.3 Wireshark-Style Packet Table

The GUI displays packets with these columns:

```text
Time | Source | Destination | Protocol | Length | Src Port | Info
```

This allows the user to inspect individual packets from the capture file.

## 6.4 Real-Time Packet Replay

The packet replay feature simulates real-time network scanning.

When the user clicks Play:

1. Packets are sorted according to timestamp.
2. Packets are inserted into a custom queue.
3. A Qt timer removes one packet at a time from the queue.
4. Each removed packet is displayed in the table.

This creates the effect of packets arriving one by one like a real network monitor.

## 6.5 Play, Pause, and Reset

The GUI includes controls for simulation:

- Play: starts releasing logs or packets one by one.
- Pause: stops the timer while keeping remaining items in the queue.
- Reset: clears the simulation and restores the full table.

If a log file is loaded, Play controls timestamp log simulation. If a PCAP file is loaded, Play controls packet replay.

## 6.6 Attack Detection

The system supports three main detection methods:

### Brute Force Detection

Brute force detection checks for repeated failed login attempts.

Condition:

```text
attackType == FAILED_LOGIN and attemptCount >= threshold
```

### Port Scan Detection

Port scan detection identifies whether a source IP is trying to connect to many different destination ports.

### Suspicious Activity Detection

Suspicious activity detection calculates total requests from each source IP and compares it with a user-defined threshold.

## 7. Data Structures Used

## 7.1 Linked List

The linked list is used to store IDS log records.

Files:

- `LogNode.h`
- `LogList.h`
- `LogList.cpp`

Each node stores:

```cpp
string srcIP;
int dstPort;
int attemptCount;
string attackType;
long timestamp;
LogNode* next;
```

The linked list supports:

- Insert log
- Display logs
- Delete logs in a time range
- Clear logs
- Convert logs to a vector for GUI display
- Run detection algorithms

### Why Linked List Was Used

A linked list is useful because logs can be inserted dynamically without needing a fixed array size. Each new log is stored as a node, and memory is allocated only when needed.

## 7.2 Custom Queue

The queue is implemented manually in:

- `CustomQueue.h`

The project does not use `std::queue` for the simulation queue. Instead, it uses a custom linked queue.

The queue contains:

```cpp
QueueNode* frontNode;
QueueNode* rearNode;
int itemCount;
```

Main operations:

```cpp
push()
pop()
front()
empty()
size()
clear()
```

### How Queue Is Used

The queue is used in two important GUI features:

```cpp
CustomQueue<LogRecord> simulationQueue;
CustomQueue<PacketRecord> packetReplayQueue;
```

For log simulation, logs are placed into `simulationQueue`.

For packet replay, packets are placed into `packetReplayQueue`.

On every timer tick, the program removes the item at the front of the queue and displays it in the table. This follows FIFO behavior, meaning the first packet inserted is the first packet displayed.

### Why Queue Was Used

Network packets arrive in order over time. A queue is the correct data structure because it follows First In, First Out order. This makes the packet replay feature behave like real network traffic.

## 7.3 Hash Tables

Hash tables are used for attack analysis and when rebuilding IDS summary logs from PCAP packets.

The project includes a separate custom hash table file:

- `CustomHashTable.h`

This file contains:

- `IntHashSet`
- `IPStatsHashTable`
- `IPStatsRecord`

`IntHashSet` stores unique destination ports. `IPStatsHashTable` stores IP-based statistics such as total requests and unique port count.

Examples:

```cpp
IPStatsHashTable ipStats;
ipStats.addPort(record.srcIP, record.dstPort);
ipStats.addRequest(record.srcIP, record.attemptCount);
```

### How Hash Tables Are Used

Hash tables are used to:

- Count packets from each source IP to each destination port.
- Store the first timestamp for each IP and port pair.
- Count TCP SYN packets.
- Track unique destination ports contacted by each source IP.

### Why Hash Tables Were Used

Hash tables provide fast lookup and grouping. This is useful for detecting port scans and repeated login attempts because the program needs to quickly count activity by IP address and port.

## 8. PCAP Processing Flow

When a PCAP file is loaded:

1. The GUI opens the selected `.pcap` file.
2. The global PCAP header is validated.
3. Each packet header is read.
4. Ethernet frames are parsed.
5. IPv4 packets are extracted.
6. TCP, UDP, and ICMP packets are identified.
7. Packet data is stored as `PacketRecord`.
8. Packet records are displayed in the GUI table.
9. Hash tables are used to create IDS summary logs.
10. Detection algorithms can be run on the generated summaries.

## 9. Simulation Flow

## 9.1 Log Timestamp Simulation

1. Logs are loaded from a log file.
2. Logs are sorted by timestamp.
3. Logs are inserted into `CustomQueue<LogRecord>`.
4. A timer removes one log at a time.
5. The table updates after each released log.

## 9.2 Packet Replay Simulation

1. A PCAP file is loaded.
2. Packets are sorted by timestamp.
3. Packets are inserted into `CustomQueue<PacketRecord>`.
4. A timer removes one packet at a time.
5. The packet table updates like a live network scanner.

## 10. GUI Design

The GUI provides:

- File loading for logs and PCAP files
- Packet table
- Log table
- Search and filtering
- Attack detection buttons
- Play, Pause, and Reset controls
- Details panel for selected rows
- Alert output panel
- Export report option

The GUI helps users interact with the IDS system without using only the command line.

## 11. Testing

The project was tested using the Qt build system.

Build command:

```powershell
E:\Program_files\Tools\CMake_64\bin\cmake.exe --build gui\build\Desktop_Qt_6_11_0_MinGW_64_bit-Debug
```

Console compile command:

```bash
g++ main.cpp LogList.cpp AttackAnalyzer.cpp -o ids
```

The build completed successfully.

Tested features include:

- Loading log files
- Loading classic PCAP files
- Displaying packets in table format
- Replaying packets one by one
- Pausing and resetting replay
- Running detection functions
- Exporting reports

## 12. Limitations

- The current direct PCAP loader supports classic `.pcap` files.
- `.pcapng` files are not supported yet.
- The PCAP parser focuses on Ethernet IPv4 packets.
- The detection rules are simple heuristic rules, not machine learning models.

## 13. Future Enhancements

- Add `.pcapng` support.
- Add packet payload preview.
- Add IP blacklist and whitelist management.
- Add charts for top suspicious IP addresses.
- Add severity-based packet coloring.
- Add automatic alert generation during packet replay.
- Add export support for CSV reports.
- Add more protocols such as DNS, HTTP, and TLS summaries.

## 14. Conclusion

Shadow IDS demonstrates how data structures can be applied to a real cybersecurity problem. The linked list stores intrusion logs, the custom queue simulates real-time packet and log arrival, and hash tables help group packet activity for fast detection.

The project successfully combines data structures, file processing, PCAP parsing, attack detection, and GUI development into one practical intrusion detection log analyzer.
