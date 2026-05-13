# Shadow IDS Source Files Guide

This file explains the purpose of each main `.cpp` and `.h` source file in the project.

Generated build files inside `gui/build/` are not included because they are created automatically by CMake and Qt.

## Root Source Files

| File | Purpose |
| --- | --- |
| `main.cpp` | Starts the command-line version of Shadow IDS. It displays the CLI banner and menu, accepts user choices, loads logs, runs detection options, and handles deleting logs by time range. |
| `LogNode.h` | Defines the `LogNode` structure used by the linked list. Each node stores one log record, including source IP, destination port, attempt count, attack type, timestamp, and a pointer to the next node. |
| `LogList.h` | Declares the `LogList` class and `LogRecord` structure. This class manages IDS logs using a linked list and exposes functions for loading, displaying, deleting, clearing, exporting, and analyzing logs. |
| `LogList.cpp` | Implements the linked list operations declared in `LogList.h`. It loads logs from a text file, inserts records, displays records, deletes logs in a time range, and calls attack detection logic. |
| `AttackAnalyzer.h` | Declares the `AttackAnalyzer` helper class. It provides static functions for detecting port scans and suspicious activity from a vector of log records. |
| `AttackAnalyzer.cpp` | Implements advanced detection logic using standard hash tables: `std::unordered_map` and `std::unordered_set`. It groups activity by source IP to find port scans and high request counts. |
| `CustomQueue.h` | Implements a custom generic queue data structure. The GUI uses it for real-time log simulation and packet replay, releasing records in first-in, first-out order. |

## GUI Source Files

| File | Purpose |
| --- | --- |
| `gui/main_gui.cpp` | Starts the Qt GUI version of Shadow IDS. It creates the `QApplication`, opens the main window, sets the window title and size, and starts the Qt event loop. |
| `gui/MainWindow.h` | Declares the `MainWindow` class for the Qt GUI. It defines GUI widgets, data records, simulation state, packet replay state, and slots used by buttons and table interactions. |
| `gui/MainWindow.cpp` | Implements the full GUI behavior. It builds the interface, loads log and PCAP files, displays logs and packets in tables, filters/searches data, runs detection, handles packet replay, and exports reports. |

## How the Files Work Together

The CLI starts from `main.cpp`, creates a `LogList` object, and calls its functions based on menu choices.

The GUI starts from `gui/main_gui.cpp`, creates a `MainWindow`, and uses the same backend classes where possible.

Shared backend files:

```text
LogNode.h
LogList.h
LogList.cpp
AttackAnalyzer.h
AttackAnalyzer.cpp
```

GUI-only support file:

```text
CustomQueue.h
```

The linked list stores log records, standard hash tables group IP activity for detection, and the custom queue controls real-time replay in the GUI.
