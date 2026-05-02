#include "MainWindow.h"

#include <QAction>
#include <QApplication>
#include <QAbstractItemView>
#include <QColor>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QKeySequence>
#include <QRegularExpression>
#include <QSize>
#include <QSplitter>
#include <QStatusBar>
#include <QStyle>
#include <QStringList>
#include <QTextStream>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent) {
    setWindowTitle("Shadow IDS - Log Analyzer");
    resize(1180, 720);

    buildMenus();
    buildToolbar();

    QWidget *central = new QWidget(this);
    QHBoxLayout *layout = new QHBoxLayout(central);
    layout->setContentsMargins(12, 10, 12, 10);
    layout->setSpacing(12);
    layout->addWidget(buildControlPanel());
    layout->addWidget(buildMainPanel(), 1);
    setCentralWidget(central);

    setProfessionalStyle();
    updateStatus();
}

void MainWindow::buildMenus() {
    QMenu *fileMenu = menuBar()->addMenu("File");

    QAction *openAction = fileMenu->addAction("Open Log File");
    openAction->setShortcut(QKeySequence::Open);
    connect(openAction, &QAction::triggered, this, &MainWindow::loadLogs);

    QAction *reloadAction = fileMenu->addAction("Reload");
    reloadAction->setShortcut(QKeySequence::Refresh);
    connect(reloadAction, &QAction::triggered, this, &MainWindow::reloadLogs);

    QAction *exportAction = fileMenu->addAction("Export Report");
    exportAction->setShortcut(QKeySequence::SaveAs);
    connect(exportAction, &QAction::triggered, this, &MainWindow::exportReport);

    fileMenu->addSeparator();
    QAction *exitAction = fileMenu->addAction("Exit");
    connect(exitAction, &QAction::triggered, this, &QWidget::close);

    QMenu *analyzeMenu = menuBar()->addMenu("Analyze");
    analyzeMenu->addAction("Detect Brute Force", this, &MainWindow::detectBruteForce);
    analyzeMenu->addAction("Detect Port Scan", this, &MainWindow::detectPortScan);
    analyzeMenu->addAction("Detect Suspicious Activity", this, &MainWindow::detectSuspiciousActivity);
    analyzeMenu->addSeparator();
    analyzeMenu->addAction("Run All Detections", this, &MainWindow::detectAll);

    QMenu *viewMenu = menuBar()->addMenu("View");
    viewMenu->addAction("Clear Output", this, &MainWindow::clearView);
    viewMenu->addAction("Refresh Table", this, &MainWindow::refreshTable);

    QMenu *helpMenu = menuBar()->addMenu("Help");
    helpMenu->addAction("About Shadow IDS", this, &MainWindow::showAbout);
}

void MainWindow::buildToolbar() {
    QToolBar *toolbar = addToolBar("Main Toolbar");
    toolbar->setMovable(false);
    toolbar->setIconSize(QSize(18, 18));

    QAction *openAction = toolbar->addAction(style()->standardIcon(QStyle::SP_DialogOpenButton), "Open");
    connect(openAction, &QAction::triggered, this, &MainWindow::loadLogs);

    QAction *reloadAction = toolbar->addAction(style()->standardIcon(QStyle::SP_BrowserReload), "Reload");
    connect(reloadAction, &QAction::triggered, this, &MainWindow::reloadLogs);

    toolbar->addSeparator();

    QAction *detectAction = toolbar->addAction(style()->standardIcon(QStyle::SP_MessageBoxWarning), "Detect All");
    connect(detectAction, &QAction::triggered, this, &MainWindow::detectAll);

    QAction *exportAction = toolbar->addAction(style()->standardIcon(QStyle::SP_DialogSaveButton), "Export");
    connect(exportAction, &QAction::triggered, this, &MainWindow::exportReport);

    QAction *clearAction = toolbar->addAction(style()->standardIcon(QStyle::SP_DialogResetButton), "Clear");
    connect(clearAction, &QAction::triggered, this, &MainWindow::clearView);
}

QWidget *MainWindow::buildControlPanel() {
    QWidget *panel = new QWidget(this);
    panel->setObjectName("controlPanel");
    panel->setFixedWidth(280);

    QLabel *title = new QLabel("Analysis Controls");
    title->setObjectName("panelTitle");

    bruteForceInput = new QLineEdit("5");
    portScanInput = new QLineEdit("3");
    suspiciousInput = new QLineEdit("10");
    startTimeInput = new QLineEdit;
    endTimeInput = new QLineEdit;

    startTimeInput->setPlaceholderText("YYYY-MM-DD HH:MM:SS");
    endTimeInput->setPlaceholderText("YYYY-MM-DD HH:MM:SS");

    QPushButton *bruteButton = new QPushButton("Detect Brute Force");
    QPushButton *portButton = new QPushButton("Detect Port Scan");
    QPushButton *suspiciousButton = new QPushButton("Detect Suspicious Activity");
    QPushButton *allButton = new QPushButton("Run All Detections");
    QPushButton *deleteButton = new QPushButton("Delete Logs In Range");

    QFormLayout *form = new QFormLayout;
    form->setLabelAlignment(Qt::AlignLeft);
    form->addRow("Failed login threshold", bruteForceInput);
    form->addRow("Unique port threshold", portScanInput);
    form->addRow("Request threshold", suspiciousInput);
    form->addRow("Start time", startTimeInput);
    form->addRow("End time", endTimeInput);

    QVBoxLayout *layout = new QVBoxLayout(panel);
    layout->setContentsMargins(14, 14, 14, 14);
    layout->setSpacing(10);
    layout->addWidget(title);
    layout->addLayout(form);
    layout->addWidget(bruteButton);
    layout->addWidget(portButton);
    layout->addWidget(suspiciousButton);
    layout->addWidget(allButton);
    layout->addSpacing(8);
    layout->addWidget(deleteButton);
    layout->addStretch();

    connect(bruteButton, &QPushButton::clicked, this, &MainWindow::detectBruteForce);
    connect(portButton, &QPushButton::clicked, this, &MainWindow::detectPortScan);
    connect(suspiciousButton, &QPushButton::clicked, this, &MainWindow::detectSuspiciousActivity);
    connect(allButton, &QPushButton::clicked, this, &MainWindow::detectAll);
    connect(deleteButton, &QPushButton::clicked, this, &MainWindow::deleteLogsInRange);

    return panel;
}

QWidget *MainWindow::buildMainPanel() {
    QWidget *panel = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(panel);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    QLabel *brand = new QLabel("Shadow IDS Packet-Style Log View");
    brand->setObjectName("mainTitle");

    filterInput = new QLineEdit;
    filterInput->setPlaceholderText("Filter logs by IP, port, type, severity, or timestamp");
    connect(filterInput, &QLineEdit::textChanged, this, &MainWindow::applyFilter);

    logTable = new QTableWidget(0, 6, this);
    logTable->setHorizontalHeaderLabels({"Time", "Source IP", "Destination Port", "Attempts", "Type", "Severity"});
    logTable->horizontalHeader()->setStretchLastSection(true);
    logTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    logTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    logTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    logTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    logTable->setSelectionMode(QAbstractItemView::SingleSelection);
    logTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    logTable->setAlternatingRowColors(true);
    logTable->verticalHeader()->setVisible(false);
    logTable->setSortingEnabled(true);
    connect(logTable, &QTableWidget::itemSelectionChanged, this, &MainWindow::showSelectedLogDetails);

    detailsPanel = new QPlainTextEdit;
    detailsPanel->setReadOnly(true);
    detailsPanel->setPlaceholderText("Select a log row to inspect details.");

    alertOutput = new QPlainTextEdit;
    alertOutput->setReadOnly(true);
    alertOutput->setPlaceholderText("Detection results and exported summaries appear here.");

    QSplitter *bottomSplitter = new QSplitter(Qt::Horizontal);
    bottomSplitter->addWidget(detailsPanel);
    bottomSplitter->addWidget(alertOutput);
    bottomSplitter->setStretchFactor(0, 1);
    bottomSplitter->setStretchFactor(1, 1);

    QSplitter *mainSplitter = new QSplitter(Qt::Vertical);
    mainSplitter->addWidget(logTable);
    mainSplitter->addWidget(bottomSplitter);
    mainSplitter->setStretchFactor(0, 3);
    mainSplitter->setStretchFactor(1, 1);

    layout->addWidget(brand);
    layout->addWidget(filterInput);
    layout->addWidget(mainSplitter, 1);

    return panel;
}

void MainWindow::loadLogs() {
    QString fileName = QFileDialog::getOpenFileName(
        this,
        "Open Log File",
        "",
        "Text Files (*.txt);;All Files (*)"
    );

    if (fileName.isEmpty()) {
        return;
    }

    currentFilePath = fileName;
    logs.clear();

    std::ostringstream buffer;
    std::streambuf *oldBuffer = std::cout.rdbuf(buffer.rdbuf());
    logs.loadFromFile(fileName.toStdString());
    std::cout.rdbuf(oldBuffer);

    refreshTable();
    appendAlert("Load Logs", QString("Loaded file: %1\n%2").arg(fileName, QString::fromStdString(buffer.str())));
}

void MainWindow::reloadLogs() {
    if (currentFilePath.isEmpty()) {
        loadLogs();
        return;
    }

    logs.clear();
    std::ostringstream buffer;
    std::streambuf *oldBuffer = std::cout.rdbuf(buffer.rdbuf());
    logs.loadFromFile(currentFilePath.toStdString());
    std::cout.rdbuf(oldBuffer);

    refreshTable();
    appendAlert("Reload Logs", QString("Reloaded file: %1\n%2").arg(currentFilePath, QString::fromStdString(buffer.str())));
}

void MainWindow::exportReport() {
    QString fileName = QFileDialog::getSaveFileName(
        this,
        "Export Report",
        "shadow_ids_report.txt",
        "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
    );

    if (fileName.isEmpty()) {
        return;
    }

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Export Failed", "Could not write the report file.");
        return;
    }

    QTextStream out(&file);
    out << "Shadow IDS Report\n";
    out << "Source file: " << (currentFilePath.isEmpty() ? "Not loaded" : currentFilePath) << "\n";
    out << "Total logs: " << logs.size() << "\n";
    out << "Visible logs: " << logTable->rowCount() << "\n";
    out << "Estimated alerts: " << alertCount() << "\n\n";
    out << "Detection Output\n";
    out << alertOutput->toPlainText() << "\n\n";
    out << "Visible Logs\n";
    out << "Time,Source IP,Destination Port,Attempts,Type,Severity\n";

    for (int row = 0; row < logTable->rowCount(); ++row) {
        QStringList cells;
        for (int col = 0; col < logTable->columnCount(); ++col) {
            cells << logTable->item(row, col)->text();
        }
        out << cells.join(",") << "\n";
    }

    appendAlert("Export Report", "Report exported to: " + fileName);
}

void MainWindow::clearView() {
    filterInput->clear();
    alertOutput->clear();
    detailsPanel->clear();
    refreshTable();
}

void MainWindow::applyFilter() {
    refreshTable();
}

void MainWindow::showSelectedLogDetails() {
    QList<QTableWidgetItem *> selected = logTable->selectedItems();
    if (selected.isEmpty()) {
        detailsPanel->clear();
        return;
    }

    int row = selected.first()->row();
    QString time = logTable->item(row, 0)->text();
    QString ip = logTable->item(row, 1)->text();
    QString port = logTable->item(row, 2)->text();
    QString attempts = logTable->item(row, 3)->text();
    QString type = logTable->item(row, 4)->text();
    QString severity = logTable->item(row, 5)->text();

    QString risk = "Routine event.";
    if (type == "FAILED_LOGIN") {
        risk = "Repeated failed authentication may indicate password guessing.";
    } else if (type.contains("SCAN", Qt::CaseInsensitive)) {
        risk = "Multiple ports or services may be under reconnaissance.";
    } else if (severity == "High") {
        risk = "High activity volume requires review.";
    }

    detailsPanel->setPlainText(
        "Selected Log Details\n\n"
        "Time: " + time + "\n"
        "Source IP: " + ip + "\n"
        "Destination Port: " + port + "\n"
        "Attempts: " + attempts + "\n"
        "Type: " + type + "\n"
        "Severity: " + severity + "\n\n"
        "Assessment: " + risk
    );
}

void MainWindow::detectBruteForce() {
    bool ok = false;
    int threshold = bruteForceInput->text().toInt(&ok);
    if (!ok || threshold <= 0) {
        QMessageBox::warning(this, "Invalid Input", "Enter a positive brute force threshold.");
        return;
    }

    appendAlert("Brute Force Detection", captureThresholdOutput(&LogList::detectBruteForce, threshold));
}

void MainWindow::detectPortScan() {
    bool ok = false;
    int threshold = portScanInput->text().toInt(&ok);
    if (!ok || threshold <= 0) {
        QMessageBox::warning(this, "Invalid Input", "Enter a positive port scan threshold.");
        return;
    }

    appendAlert("Port Scan Detection", captureThresholdOutput(&LogList::detectPortScan, threshold));
}

void MainWindow::detectSuspiciousActivity() {
    bool ok = false;
    int threshold = suspiciousInput->text().toInt(&ok);
    if (!ok || threshold <= 0) {
        QMessageBox::warning(this, "Invalid Input", "Enter a positive request threshold.");
        return;
    }

    appendAlert("Suspicious Activity Detection", captureThresholdOutput(&LogList::detectSuspiciousActivity, threshold));
}

void MainWindow::detectAll() {
    detectBruteForce();
    detectPortScan();
    detectSuspiciousActivity();
}

void MainWindow::deleteLogsInRange() {
    long startTime = 0;
    long endTime = 0;

    if (!parseDateTime(startTimeInput->text(), startTime) ||
        !parseDateTime(endTimeInput->text(), endTime)) {
        QMessageBox::warning(this, "Invalid Date", "Use this format: YYYY-MM-DD HH:MM:SS");
        return;
    }

    logs.deleteLogsInRange(startTime, endTime);
    refreshTable();
    appendAlert("Delete Logs", "Logs in the selected time range were deleted.");
}

void MainWindow::showAbout() {
    QMessageBox::about(
        this,
        "About Shadow IDS",
        "Shadow IDS - Log Analyzer\n\n"
        "A Qt-based intrusion detection log viewer with filtering, table analysis, and report export."
    );
}

void MainWindow::refreshTable() {
    populateTable(filteredRecords());
    updateStatus();
}

void MainWindow::populateTable(const QVector<LogRecord> &records) {
    logTable->setSortingEnabled(false);
    logTable->setRowCount(0);

    for (const LogRecord &record : records) {
        int row = logTable->rowCount();
        logTable->insertRow(row);

        QString severity = severityForRecord(record);
        QStringList values = {
            formatTimestamp(record.timestamp),
            QString::fromStdString(record.srcIP),
            QString::number(record.dstPort),
            QString::number(record.attemptCount),
            QString::fromStdString(record.attackType),
            severity
        };

        QColor background = QColor("#ffffff");
        if (severity == "Critical") {
            background = QColor("#ffd6d6");
        } else if (severity == "High") {
            background = QColor("#ffe8bf");
        } else if (severity == "Medium") {
            background = QColor("#fff7c2");
        }

        for (int col = 0; col < values.size(); ++col) {
            QTableWidgetItem *item = new QTableWidgetItem(values[col]);
            item->setBackground(background);
            item->setForeground(QColor("#1f2933"));
            logTable->setItem(row, col, item);
        }
    }

    logTable->setSortingEnabled(true);
}

QVector<LogRecord> MainWindow::filteredRecords() const {
    QVector<LogRecord> records;
    QString filter = filterInput->text().trimmed();

    for (const LogRecord &record : logs.getLogs()) {
        QString combined = QString("%1 %2 %3 %4 %5 %6")
            .arg(formatTimestamp(record.timestamp))
            .arg(QString::fromStdString(record.srcIP))
            .arg(record.dstPort)
            .arg(record.attemptCount)
            .arg(QString::fromStdString(record.attackType))
            .arg(severityForRecord(record));

        if (filter.isEmpty() || combined.contains(filter, Qt::CaseInsensitive)) {
            records.append(record);
        }
    }

    return records;
}

void MainWindow::updateStatus() {
    statusBar()->showMessage(
        QString("Loaded logs: %1 | Visible: %2 | Estimated alerts: %3 | File: %4")
            .arg(logs.size())
            .arg(logTable ? logTable->rowCount() : 0)
            .arg(alertCount())
            .arg(currentFilePath.isEmpty() ? "No file loaded" : currentFilePath)
    );
}

void MainWindow::appendAlert(const QString &title, const QString &content) {
    QString cleaned = cleanConsoleOutput(content).trimmed();
    alertOutput->appendPlainText("===== " + title + " =====");
    alertOutput->appendPlainText(cleaned.isEmpty() ? "No output." : cleaned);
    alertOutput->appendPlainText("");
    updateStatus();
}

void MainWindow::setProfessionalStyle() {
    qApp->setStyleSheet(R"(
        QMainWindow, QWidget {
            background: #f3f5f7;
            color: #1f2933;
            font-family: Segoe UI, Arial, sans-serif;
            font-size: 10pt;
        }

        QMenuBar, QMenu, QToolBar {
            background: #ffffff;
            border-bottom: 1px solid #d8dee6;
        }

        QToolButton {
            padding: 5px 8px;
            border: 1px solid transparent;
            border-radius: 4px;
        }

        QToolButton:hover {
            background: #e8f1ff;
            border-color: #b7c7dd;
        }

        #controlPanel {
            background: #ffffff;
            border: 1px solid #d8dee6;
            border-radius: 6px;
        }

        #panelTitle, #mainTitle {
            font-size: 15pt;
            font-weight: 700;
            color: #17202a;
        }

        QLineEdit {
            background: #ffffff;
            border: 1px solid #b9c3cf;
            border-radius: 4px;
            padding: 7px 8px;
        }

        QLineEdit:focus {
            border: 1px solid #2672c9;
        }

        QPushButton {
            background: #ffffff;
            border: 1px solid #b9c3cf;
            border-radius: 4px;
            padding: 7px 10px;
            text-align: center;
        }

        QPushButton:hover {
            background: #eaf3ff;
            border-color: #7da7d9;
        }

        QPushButton:pressed {
            background: #d8eaff;
        }

        QTableWidget {
            background: #ffffff;
            alternate-background-color: #f8fafc;
            gridline-color: #dde3ea;
            border: 1px solid #cfd7e2;
            selection-background-color: #cfe4ff;
            selection-color: #111827;
        }

        QHeaderView::section {
            background: #e7edf3;
            color: #1f2933;
            border: 0;
            border-right: 1px solid #c8d1dc;
            border-bottom: 1px solid #c8d1dc;
            padding: 7px;
            font-weight: 600;
        }

        QPlainTextEdit {
            background: #ffffff;
            border: 1px solid #cfd7e2;
            border-radius: 4px;
            padding: 8px;
            font-family: Consolas, Cascadia Mono, monospace;
        }

        QStatusBar {
            background: #ffffff;
            border-top: 1px solid #d8dee6;
        }
    )");
}

QString MainWindow::formatTimestamp(long timestamp) const {
    QDateTime dateTime = QDateTime::fromSecsSinceEpoch(timestamp);
    return dateTime.toString("yyyy-MM-dd HH:mm:ss");
}

QString MainWindow::severityForRecord(const LogRecord &record) const {
    QString type = QString::fromStdString(record.attackType);

    if (type == "FAILED_LOGIN" && record.attemptCount >= 5) {
        return "Critical";
    }

    if (type.contains("SCAN", Qt::CaseInsensitive)) {
        return "High";
    }

    if (record.attemptCount >= 10) {
        return "High";
    }

    if (record.attemptCount >= 5) {
        return "Medium";
    }

    return "Low";
}

int MainWindow::alertCount() const {
    int count = 0;
    for (const LogRecord &record : logs.getLogs()) {
        QString severity = severityForRecord(record);
        if (severity == "Critical" || severity == "High") {
            count++;
        }
    }
    return count;
}

QString MainWindow::cleanConsoleOutput(const QString &content) const {
    QString cleaned = content;
    cleaned.remove(QRegularExpression("\\x1B\\[[0-9;]*[A-Za-z]"));
    return cleaned;
}

QString MainWindow::captureThresholdOutput(void (LogList::*action)(int), int threshold) {
    std::ostringstream buffer;
    std::streambuf *oldBuffer = std::cout.rdbuf(buffer.rdbuf());
    (logs.*action)(threshold);
    std::cout.rdbuf(oldBuffer);
    return QString::fromStdString(buffer.str());
}

bool MainWindow::parseDateTime(const QString &input, long &timestamp) const {
    std::tm timeInfo = {};
    std::istringstream stream(input.toStdString());
    stream >> std::get_time(&timeInfo, "%Y-%m-%d %H:%M:%S");

    if (stream.fail()) {
        return false;
    }

    timestamp = static_cast<long>(std::mktime(&timeInfo));
    return timestamp != -1;
}
