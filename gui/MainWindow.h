#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QLineEdit>
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QTableWidget>

#include "../LogList.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void loadLogs();
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
    QTableWidget *logTable;
    QPlainTextEdit *detailsPanel;
    QPlainTextEdit *alertOutput;

    void buildMenus();
    void buildToolbar();
    QWidget *buildControlPanel();
    QWidget *buildMainPanel();
    void refreshTable();
    void populateTable(const QVector<LogRecord> &records);
    QVector<LogRecord> filteredRecords() const;
    void updateStatus();
    void appendAlert(const QString &title, const QString &content);
    void setProfessionalStyle();
    QString formatTimestamp(long timestamp) const;
    QString severityForRecord(const LogRecord &record) const;
    int alertCount() const;
    QString cleanConsoleOutput(const QString &content) const;
    QString captureThresholdOutput(void (LogList::*action)(int), int threshold);
    bool parseDateTime(const QString &input, long &timestamp) const;
};

#endif
