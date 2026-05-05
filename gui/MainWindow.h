#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QLineEdit>
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>

#include "../CustomQueue.h"
#include "../LogList.h"

#include <cstdint>

struct PacketRecord {
    long timestamp;
    QString srcIP;
    QString dstIP;
    int srcPort;
    int dstPort;
    QString protocol;
    int length;
    QString info;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void loadLogs();
    void loadPcap();
    void reloadLogs();
    void exportReport();
    void clearView();
    void applyFilter();
    void showSelectedLogDetails();
    void detectBruteForce();
    void detectPortScan();
    void detectSuspiciousActivity();
    void detectAll();
    void deleteLogsInRange();
    void startSimulation();
    void pauseSimulation();
    void resetSimulation();
    void processNextSimulationLog();
    void startPacketReplay();
    void pausePacketReplay();
    void resetPacketReplay();
    void processNextPacket();
    void showAbout();

private:
    LogList logs;

    QString currentFilePath;
    QLineEdit *filterInput;
    QLineEdit *bruteForceInput;
    QLineEdit *portScanInput;
    QLineEdit *suspiciousInput;
    QLineEdit *startTimeInput;
    QLineEdit *endTimeInput;
    QPushButton *playButton;
    QPushButton *pauseButton;
    QPushButton *resetSimulationButton;
    QTableWidget *logTable;
    QPlainTextEdit *detailsPanel;
    QPlainTextEdit *alertOutput;
    QTimer *simulationTimer;
    QTimer *packetReplayTimer;
    CustomQueue<LogRecord> simulationQueue;
    CustomQueue<PacketRecord> packetReplayQueue;
    QVector<LogRecord> simulatedRecords;
    QVector<PacketRecord> packetRecords;
    QVector<PacketRecord> displayedPackets;
    bool simulationMode;
    bool packetMode;
    bool packetReplayMode;

    void buildMenus();
    void buildToolbar();
    QWidget *buildControlPanel();
    QWidget *buildMainPanel();
    void refreshTable();
    void populateTable(const QVector<LogRecord> &records);
    void populatePacketTable(const QVector<PacketRecord> &records);
    QVector<LogRecord> filteredRecords() const;
    QVector<PacketRecord> filteredPacketRecords() const;
    void updateStatus();
    void appendAlert(const QString &title, const QString &content);
    void setProfessionalStyle();
    void setSimulationControls(bool playing);
    void clearSimulationQueue();
    void clearPacketReplayQueue();
    bool loadPacketsFromPcap(const QString &fileName, QString &errorMessage);
    void rebuildLogsFromPackets();
    void showPacketMode();
    std::uint32_t readUInt32(const QByteArray &bytes, int offset, bool littleEndian) const;
    QString ipv4ToString(const uchar *bytes) const;
    QString formatTimestamp(long timestamp) const;
    QString severityForRecord(const LogRecord &record) const;
    int alertCount() const;
    QString cleanConsoleOutput(const QString &content) const;
    QString captureThresholdOutput(void (LogList::*action)(int), int threshold);
    bool parseDateTime(const QString &input, long &timestamp) const;
};

#endif
