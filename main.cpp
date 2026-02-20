#include <iostream>
#include <ctime>
#include "LogList.h"

using namespace std;

// Function to display Shadow IDS banner
void showBanner() {
    
cout << "\033[31m"; // set red color

cout << R"(███╗   ██╗███████╗████████╗███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
██╔██╗ ██║█████╗     ██║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
██║ ╚████║███████╗   ██║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ )"<<endl;

 cout << "\033[0m"; // reset color
}






int main() {
    LogList logs;
    int choice;

    // Display banner at program start
    showBanner();

    while (true) {
        cout << "\n===== Shadow IDS Menu =====\n";
        cout << "1. Load logs from file\n";
        cout << "2. Display all logs\n";
        cout << "3. Detect brute force attacks\n";
        cout << "4. Detect port scan attacks\n";
        cout << "5. Detect suspicious activity\n";
        cout << "6. Delete old logs\n";
        cout << "7. Exit\n";
        cout << "Enter your choice: ";
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
            long expiry;
            cout << "Enter expiry time (seconds): ";
            cin >> expiry;
            long now = time(NULL);
            logs.deleteOldLogs(now, expiry);
            cout << "Old logs deleted.\n";
        }
        else if (choice == 7) {
            cout << "Exiting Shadow IDS...\n";
            break;
        }
        else {
            cout << "Invalid choice. Try again.\n";
        }
    }

    return 0;
}


