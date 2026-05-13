# Shadow IDS - CLI and GUI Comparison

## 1. Overview

Shadow IDS has two user interfaces:

- CLI mode
- GUI mode

Both modes use the same core backend logic for storing logs and detecting attacks. The CLI provides a simple menu-based interface, while the GUI provides a visual interface with extra features such as PCAP loading, packet replay, filtering, and report export.

## 2. Shared Backend Logic

The CLI and GUI are connected through shared C++ classes.

Shared files:

| File | Purpose |
| --- | --- |
| `LogNode.h` | Defines one linked list node |
| `LogList.h` | Declares linked list operations and detection methods |
| `LogList.cpp` | Implements log storage and detection function calls |
| `AttackAnalyzer.h` | Declares attack analysis helper functions |
| `AttackAnalyzer.cpp` | Uses the custom hash table for improved detection |
| `CustomHashTable.h` | Implements hash table and hash set logic |

The CLI uses this backend from:

```text
main.cpp
```

The GUI uses the same backend from:

```text
gui/MainWindow.cpp
```

This means the GUI is not a completely separate system. It is built on top of the same IDS logic used by the CLI.

## 3. Is CLI Integrated Into GUI?

The GUI does not open the text-based CLI menu inside the window.

Instead, the GUI integrates the CLI backend logic.

For example, the CLI directly calls:

```cpp
logs.detectBruteForce(threshold);
```

The GUI also calls the same function, but captures the console output and displays it in the GUI alert panel:

```cpp
appendAlert("Brute Force Detection", captureThresholdOutput(&LogList::detectBruteForce, threshold));
```

So the correct explanation is:

```text
The GUI is integrated with the CLI backend logic. Both CLI and GUI use the same LogList and AttackAnalyzer detection functions.
```

## 4. CLI Mode Capabilities

CLI mode is simple and menu based.

| Capability | CLI Mode |
| --- | --- |
| Load log file | Yes |
| Display all logs | Yes |
| Detect brute force attacks | Yes |
| Detect port scan attacks | Yes |
| Detect suspicious activity | Yes |
| Delete logs by time range | Yes |
| Use linked list for log storage | Yes |
| Use custom hash table for detection | Yes |
| Load PCAP directly | No |
| View individual packets | No |
| Real-time packet replay | No |
| Export report | No |

CLI mode is useful for demonstrating the basic IDS functionality and linked list operations.

## 5. GUI Mode Capabilities

GUI mode includes all main CLI detection features and adds visual features.

| Capability | GUI Mode |
| --- | --- |
| Load log file | Yes |
| Display logs in table | Yes |
| Detect brute force attacks | Yes |
| Detect port scan attacks | Yes |
| Detect suspicious activity | Yes |
| Delete logs by time range | Yes |
| Load PCAP directly | Yes |
| View individual packets | Yes |
| Wireshark-style packet table | Yes |
| Real-time timestamp log simulation | Yes |
| Real-time packet replay | Yes |
| Play, Pause, Reset controls | Yes |
| Filter/search logs or packets | Yes |
| Select row and view details | Yes |
| Export report | Yes |
| Reload current file | Yes |
| Colored severity display | Yes |

GUI mode is useful for demonstrating the complete project with linked list, queue, and hash table data structures.

## 6. CLI vs GUI Feature Table

| Capability | CLI Mode | GUI Mode |
| --- | --- | --- |
| Load `logs.txt` style log file | Yes | Yes |
| Display all logs | Yes | Yes, table format |
| Detect brute force attacks | Yes | Yes |
| Detect port scan attacks | Yes | Yes |
| Detect suspicious activity | Yes | Yes |
| Delete logs by time range | Yes | Yes |
| Linked list log storage | Yes | Yes |
| Custom hash table detection | Yes | Yes |
| Direct PCAP loading | No | Yes |
| Individual packet view | No | Yes |
| Wireshark-style packet table | No | Yes |
| Timestamp log simulation | No | Yes |
| Real-time packet replay | No | Yes |
| Custom queue replay | No | Yes |
| Play / Pause / Reset | No | Yes |
| Search and filtering | No | Yes |
| Row detail panel | No | Yes |
| Export report | No | Yes |

## 7. Data Structures by Mode

## CLI Mode

CLI mode uses:

- Linked list for storing logs
- Custom hash table for improved detection

Main files:

```text
LogNode.h
LogList.h
LogList.cpp
AttackAnalyzer.h
AttackAnalyzer.cpp
CustomHashTable.h
```

## GUI Mode

GUI mode uses:

- Linked list for storing logs
- Custom hash table for detection
- Custom queue for real-time replay

Main files:

```text
gui/MainWindow.h
gui/MainWindow.cpp
CustomQueue.h
CustomHashTable.h
LogList.h
LogList.cpp
AttackAnalyzer.h
AttackAnalyzer.cpp
```

## 8. Evaluator-Friendly Explanation

You can explain the difference like this:

```text
The CLI is the basic version of the IDS. It loads logs, stores them in a linked list, and runs attack detection.

The GUI is the advanced version. It uses the same backend logic as the CLI, but adds direct PCAP loading, packet viewing, filtering, report exporting, and real-time replay.

The linked list stores logs, the custom hash table groups IP activity for detection, and the custom queue releases packets or logs one by one during simulation.
```

## 9. Conclusion

The CLI and GUI are not separate projects. They are two interfaces for the same IDS system.

The CLI is useful for showing core logic clearly. The GUI is useful for showing the complete system with visual packet analysis and real-time simulation.

