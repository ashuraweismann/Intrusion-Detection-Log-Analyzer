#include <iostream>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>
#include "LogList.h"

using namespace std;

const char* BLUE = "\033[34m";
const char* MAGENTA = "\033[35m";
const char* WHITE = "\033[37m";
const char* YELLOW = "\033[33m";
const char* RESET = MAGENTA;

void showMenu() {
    cout << BLUE;
    cout << "\n===== Shadow IDS Menu =====\n";
    cout << "1. Load logs from file\n";
    cout << "2. Display all logs\n";
    cout << "3. Detect brute force attacks\n";
    cout << "4. Detect port scan attacks\n";
    cout << "5. Detect suspicious activity\n";
    cout << "6. Delete logs in time range\n";
    cout << "7. Exit\n";
    cout << RESET;
}

// Function to display Shadow IDS banner
void showBanner() {
    
cout << "\033[31m"; // set red color

cout << R"(███╗   ██╗███████╗████████╗███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
██╔██╗ ██║█████╗     ██║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
██║ ╚████║███████╗   ██║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ )"<<endl;

 cout << MAGENTA; // default text color after banner
}

bool parseDateTime(const string& input, long& timestamp) {
    tm timeInfo = {};
    istringstream stream(input);
    stream >> get_time(&timeInfo, "%Y-%m-%d %H:%M:%S");

    if (stream.fail()) {
        return false;
    }

    timestamp = static_cast<long>(mktime(&timeInfo));
    return timestamp != -1;
}






int main() {
    LogList logs;
    int choice;

    // Display banner at program start
    showBanner();
    showMenu();

    while (true) {
        cout << "\nEnter your choice (1-7): ";
        cin >> choice;

        if (choice == 1) {
            logs.loadFromFile("logs.txt");
        }
        else if (choice == 2) {
            logs.displayLogs();
        }
        else if (choice == 3) {
            int threshold;
            cout << "Enter attempt threshold: ";
            cin >> threshold;
            logs.detectBruteForce(threshold);
        }
        else if (choice == 4) {
            int portThreshold;
            cout << "Enter port scan threshold: ";
            cin >> portThreshold;
            logs.detectPortScan(portThreshold);
        }
        else if (choice == 5) {
            int requestThreshold;
            cout << "Enter request threshold: ";
            cin >> requestThreshold;
            logs.detectSuspiciousActivity(requestThreshold);
        }
        else if (choice == 6) {
            long startTime, endTime;
            string startInput, endInput;

            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Enter start time (format: YYYY-MM-DD HH:MM:SS): ";
            getline(cin, startInput);
            cout << "Enter end time (format: YYYY-MM-DD HH:MM:SS): ";
            getline(cin, endInput);

            if (!parseDateTime(startInput, startTime) ||
                !parseDateTime(endInput, endTime)) {
                cout << YELLOW
                     << "[INFO] Invalid date/time input. Use format: YYYY-MM-DD HH:MM:SS\n"
                     << MAGENTA;
                continue;
            }

            logs.deleteLogsInRange(startTime, endTime);
            cout << "Logs in the given time range were deleted.\n";
        }
        else if (choice == 7) {
            cout << WHITE << "Exiting Shadow IDS...\n";
            break;
        }
        else {
            cout << "Invalid choice. Try again.\n";
        }
    }

    cout << WHITE;
    return 0;
}


