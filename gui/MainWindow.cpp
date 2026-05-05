#include "MainWindow.h"

#include <QAction>
#include <QApplication>
#include <QAbstractItemView>
#include <QColor>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
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

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace {
const int PacketReplayIntervalMs = 450;
const std::unordered_set<int> LoginPorts = {
    21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 3389
};
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      simulationTimer(new QTimer(this)),
      packetReplayTimer(new QTimer(this)),
      simulationMode(false),
      packetMode(false),
      packetReplayMode(false) {
    setWindowTitle("Shadow IDS - Log Analyzer");
    resize(1180, 720);

    simulationTimer->setInterval(700);
    connect(simulationTimer, &QTimer::timeout, this, &MainWindow::processNextSimulationLog);
    packetReplayTimer->setInterval(PacketReplayIntervalMs);
    connect(packetReplayTimer, &QTimer::timeout, this, &MainWindow::processNextPacket);

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

    QAction *openPcapAction = fileMenu->addAction("Open PCAP File");
    connect(openPcapAction, &QAction::triggered, this, &MainWindow::loadPcap);

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
    analyzeMenu->addAction("Play Timestamp Simulation", this, &MainWindow::startSimulation);
    analyzeMenu->addAction("Pause Simulation", this, &MainWindow::pauseSimulation);
    analyzeMenu->addAction("Reset Simulation", this, &MainWindow::resetSimulation);
    analyzeMenu->addSeparator();
    analyzeMenu->addAction("Play Packet Replay", this, &MainWindow::startPacketReplay);
    analyzeMenu->addAction("Pause Packet Replay", this, &MainWindow::pausePacketReplay);
    analyzeMenu->addAction("Reset Packet Replay", this, &MainWindow::resetPacketReplay);
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

    QAction *openPcapAction = toolbar->addAction(style()->standardIcon(QStyle::SP_DriveNetIcon), "Open PCAP");
    connect(openPcapAction, &QAction::triggered, this, &MainWindow::loadPcap);

    QAction *reloadAction = toolbar->addAction(style()->standardIcon(QStyle::SP_BrowserReload), "Reload");
    connect(reloadAction, &QAction::triggered, this, &MainWindow::reloadLogs);

    toolbar->addSeparator();

    QAction *detectAction = toolbar->addAction(style()->standardIcon(QStyle::SP_MessageBoxWarning), "Detect All");
    connect(detectAction, &QAction::triggered, this, &MainWindow::detectAll);

    QAction *playAction = toolbar->addAction(style()->standardIcon(QStyle::SP_MediaPlay), "Play");
    connect(playAction, &QAction::triggered, this, [this]() {
        packetMode ? startPacketReplay() : startSimulation();
    });

    QAction *pauseAction = toolbar->addAction(style()->standardIcon(QStyle::SP_MediaPause), "Pause");
    connect(pauseAction, &QAction::triggered, this, [this]() {
        packetMode ? pausePacketReplay() : pauseSimulation();
    });

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
    playButton = new QPushButton(style()->standardIcon(QStyle::SP_MediaPlay), "Play");
    pauseButton = new QPushButton(style()->standardIcon(QStyle::SP_MediaPause), "Pause");
    resetSimulationButton = new QPushButton(style()->standardIcon(QStyle::SP_BrowserReload), "Reset");

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
    layout->addWidget(new QLabel("Timestamp Simulator"));
    layout->addWidget(playButton);
    layout->addWidget(pauseButton);
    layout->addWidget(resetSimulationButton);
    layout->addSpacing(8);
    layout->addWidget(deleteButton);
    layout->addStretch();

    connect(bruteButton, &QPushButton::clicked, this, &MainWindow::detectBruteForce);
    connect(portButton, &QPushButton::clicked, this, &MainWindow::detectPortScan);
    connect(suspiciousButton, &QPushButton::clicked, this, &MainWindow::detectSuspiciousActivity);
    connect(allButton, &QPushButton::clicked, this, &MainWindow::detectAll);
    connect(deleteButton, &QPushButton::clicked, this, &MainWindow::deleteLogsInRange);
    connect(playButton, &QPushButton::clicked, this, [this]() {
        packetMode ? startPacketReplay() : startSimulation();
    });
    connect(pauseButton, &QPushButton::clicked, this, [this]() {
        packetMode ? pausePacketReplay() : pauseSimulation();
    });
    connect(resetSimulationButton, &QPushButton::clicked, this, [this]() {
        packetMode ? resetPacketReplay() : resetSimulation();
    });

    setSimulationControls(false);

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
    clearSimulationQueue();
    clearPacketReplayQueue();
    simulatedRecords.clear();
    packetRecords.clear();
    displayedPackets.clear();
    simulationMode = false;
    packetMode = false;
    packetReplayMode = false;

    std::ostringstream buffer;
    std::streambuf *oldBuffer = std::cout.rdbuf(buffer.rdbuf());
    logs.loadFromFile(fileName.toStdString());
    std::cout.rdbuf(oldBuffer);

    refreshTable();
    appendAlert("Load Logs", QString("Loaded file: %1\n%2").arg(fileName, QString::fromStdString(buffer.str())));
}

void MainWindow::loadPcap() {
    QString fileName = QFileDialog::getOpenFileName(
        this,
        "Open PCAP File",
        "",
        "PCAP Files (*.pcap);;All Files (*)"
    );

    if (fileName.isEmpty()) {
        return;
    }

    QString errorMessage;
    if (!loadPacketsFromPcap(fileName, errorMessage)) {
        QMessageBox::warning(this, "PCAP Load Failed", errorMessage);
        return;
    }

    currentFilePath = fileName;
    rebuildLogsFromPackets();
    showPacketMode();
    appendAlert(
        "Load PCAP",
        QString("Loaded %1 IPv4 TCP/UDP/ICMP packets from: %2\nGenerated %3 IDS summary rows for detection.")
            .arg(packetRecords.size())
            .arg(fileName)
            .arg(logs.size())
    );
}

void MainWindow::reloadLogs() {
    if (currentFilePath.isEmpty()) {
        loadLogs();
        return;
    }

    if (QFileInfo(currentFilePath).suffix().compare("pcap", Qt::CaseInsensitive) == 0) {
        QString errorMessage;
        if (!loadPacketsFromPcap(currentFilePath, errorMessage)) {
            QMessageBox::warning(this, "PCAP Reload Failed", errorMessage);
            return;
        }
        rebuildLogsFromPackets();
        showPacketMode();
        appendAlert("Reload PCAP", QString("Reloaded %1 packets from: %2").arg(packetRecords.size()).arg(currentFilePath));
        return;
    }

    logs.clear();
    clearSimulationQueue();
    clearPacketReplayQueue();
    simulatedRecords.clear();
    packetRecords.clear();
    displayedPackets.clear();
    simulationMode = false;
    packetMode = false;
    packetReplayMode = false;
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
    out << (packetMode ? "Visible Packets\n" : "Visible Logs\n");
    if (packetMode) {
        out << "Time,Source,Destination,Protocol,Length,Source Port,Info\n";
    } else {
        out << "Time,Source IP,Destination Port,Attempts,Type,Severity\n";
    }

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
    resetSimulation();
    resetPacketReplay();
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

    if (packetMode) {
        QString time = logTable->item(row, 0)->text();
        QString src = logTable->item(row, 1)->text();
        QString dst = logTable->item(row, 2)->text();
        QString protocol = logTable->item(row, 3)->text();
        QString length = logTable->item(row, 4)->text();
        QString srcPort = logTable->item(row, 5)->text();
        QString info = logTable->item(row, 6)->text();

        QString assessment = "Network packet captured from the PCAP stream.";
        if (protocol == "TCP" && info.contains("SYN", Qt::CaseInsensitive) &&
            !info.contains("ACK", Qt::CaseInsensitive)) {
            assessment = "TCP SYN packet; repeated SYNs can indicate probing, login attempts, or scanning.";
        } else if (protocol == "ICMP") {
            assessment = "ICMP control packet; useful for spotting ping sweeps or reachability checks.";
        }

        detailsPanel->setPlainText(
            "Selected Packet Details\n\n"
            "Time: " + time + "\n"
            "Source: " + src + "\n"
            "Destination: " + dst + "\n"
            "Protocol: " + protocol + "\n"
            "Length: " + length + "\n"
            "Source Port: " + srcPort + "\n"
            "Info: " + info + "\n\n"
            "Assessment: " + assessment
        );
        return;
    }

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
    resetSimulation();
    refreshTable();
    appendAlert("Delete Logs", "Logs in the selected time range were deleted.");
}

void MainWindow::startSimulation() {
    if (packetMode) {
        QMessageBox::information(this, "Packet View Active", "Use Packet Replay for PCAP packet simulation.");
        return;
    }

    if (logs.size() == 0) {
        QMessageBox::information(this, "No Logs Loaded", "Load a log file before starting the simulator.");
        return;
    }

    if (!simulationMode || (simulationQueue.empty() && simulatedRecords.isEmpty())) {
        QVector<LogRecord> records;
        for (const LogRecord &record : logs.getLogs()) {
            records.append(record);
        }

        std::sort(records.begin(), records.end(), [](const LogRecord &left, const LogRecord &right) {
            return left.timestamp < right.timestamp;
        });

        clearSimulationQueue();
        simulatedRecords.clear();
        for (const LogRecord &record : records) {
            simulationQueue.push(record);
        }

        simulationMode = true;
        populateTable(simulatedRecords);
        appendAlert("Timestamp Simulator", QString("Simulation queued %1 logs in timestamp order.").arg(records.size()));
    }

    if (simulationQueue.empty()) {
        appendAlert("Timestamp Simulator", "Simulation already finished. Reset to replay from the beginning.");
        setSimulationControls(false);
        return;
    }

    simulationTimer->start();
    setSimulationControls(true);
    updateStatus();
}

void MainWindow::pauseSimulation() {
    simulationTimer->stop();
    setSimulationControls(false);
    updateStatus();
}

void MainWindow::resetSimulation() {
    simulationTimer->stop();
    clearSimulationQueue();
    simulatedRecords.clear();
    simulationMode = false;
    setSimulationControls(false);
    if (!packetMode) {
        refreshTable();
    }
}

void MainWindow::processNextSimulationLog() {
    if (simulationQueue.empty()) {
        simulationTimer->stop();
        setSimulationControls(false);
        appendAlert("Timestamp Simulator", "Simulation complete.");
        return;
    }

    simulatedRecords.append(simulationQueue.front());
    simulationQueue.pop();
    populateTable(filteredRecords());
    updateStatus();

    if (simulationQueue.empty()) {
        simulationTimer->stop();
        setSimulationControls(false);
        appendAlert("Timestamp Simulator", "Simulation complete.");
    }
}

void MainWindow::startPacketReplay() {
    if (packetRecords.isEmpty()) {
        QMessageBox::information(this, "No PCAP Loaded", "Load a PCAP file before starting packet replay.");
        return;
    }

    if (!packetReplayMode || (packetReplayQueue.empty() && displayedPackets.isEmpty())) {
        clearPacketReplayQueue();
        displayedPackets.clear();

        QVector<PacketRecord> records = packetRecords;
        std::sort(records.begin(), records.end(), [](const PacketRecord &left, const PacketRecord &right) {
            return left.timestamp < right.timestamp;
        });

        for (const PacketRecord &record : records) {
            packetReplayQueue.push(record);
        }

        packetMode = true;
        packetReplayMode = true;
        populatePacketTable(displayedPackets);
        appendAlert("Packet Replay", QString("Queued %1 packets for real-time replay.").arg(records.size()));
    }

    if (packetReplayQueue.empty()) {
        appendAlert("Packet Replay", "Replay already finished. Reset to replay from the beginning.");
        setSimulationControls(false);
        return;
    }

    packetReplayTimer->start();
    setSimulationControls(true);
    updateStatus();
}

void MainWindow::pausePacketReplay() {
    packetReplayTimer->stop();
    setSimulationControls(false);
    updateStatus();
}

void MainWindow::resetPacketReplay() {
    packetReplayTimer->stop();
    clearPacketReplayQueue();
    displayedPackets.clear();
    packetReplayMode = false;
    setSimulationControls(false);

    if (packetMode) {
        populatePacketTable(packetRecords);
        updateStatus();
    }
}

void MainWindow::processNextPacket() {
    if (packetReplayQueue.empty()) {
        packetReplayTimer->stop();
        setSimulationControls(false);
        appendAlert("Packet Replay", "Replay complete.");
        return;
    }

    displayedPackets.append(packetReplayQueue.front());
    packetReplayQueue.pop();
    populatePacketTable(filteredPacketRecords());
    updateStatus();

    if (packetReplayQueue.empty()) {
        packetReplayTimer->stop();
        setSimulationControls(false);
        appendAlert("Packet Replay", "Replay complete.");
    }
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
    if (packetMode) {
        populatePacketTable(filteredPacketRecords());
    } else {
        populateTable(filteredRecords());
    }
    updateStatus();
}

void MainWindow::populateTable(const QVector<LogRecord> &records) {
    logTable->setColumnCount(6);
    logTable->setHorizontalHeaderLabels({"Time", "Source IP", "Destination Port", "Attempts", "Type", "Severity"});
    logTable->horizontalHeader()->setStretchLastSection(true);
    logTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    logTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    logTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

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

void MainWindow::populatePacketTable(const QVector<PacketRecord> &records) {
    logTable->setColumnCount(7);
    logTable->setHorizontalHeaderLabels({"Time", "Source", "Destination", "Protocol", "Length", "Src Port", "Info"});
    logTable->horizontalHeader()->setStretchLastSection(true);
    logTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    logTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    logTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    logTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    logTable->setSortingEnabled(false);
    logTable->setRowCount(0);

    for (const PacketRecord &record : records) {
        int row = logTable->rowCount();
        logTable->insertRow(row);

        QStringList values = {
            formatTimestamp(record.timestamp),
            record.srcIP,
            record.dstIP,
            record.protocol,
            QString::number(record.length),
            record.srcPort > 0 ? QString::number(record.srcPort) : "-",
            record.info
        };

        QColor background = QColor("#ffffff");
        if (record.protocol == "TCP" && record.info.contains("SYN", Qt::CaseInsensitive)) {
            background = QColor("#fff7c2");
        } else if (record.protocol == "ICMP") {
            background = QColor("#e6f4ff");
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

    QVector<LogRecord> sourceRecords;
    if (simulationMode) {
        sourceRecords = simulatedRecords;
    } else {
        for (const LogRecord &record : logs.getLogs()) {
            sourceRecords.append(record);
        }
    }

    for (const LogRecord &record : sourceRecords) {
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

QVector<PacketRecord> MainWindow::filteredPacketRecords() const {
    QVector<PacketRecord> records;
    QString filter = filterInput->text().trimmed();
    const QVector<PacketRecord> &sourceRecords = packetReplayMode ? displayedPackets : packetRecords;

    for (const PacketRecord &record : sourceRecords) {
        QString combined = QString("%1 %2 %3 %4 %5 %6 %7")
            .arg(formatTimestamp(record.timestamp))
            .arg(record.srcIP)
            .arg(record.dstIP)
            .arg(record.protocol)
            .arg(record.length)
            .arg(record.srcPort)
            .arg(record.info);

        if (filter.isEmpty() || combined.contains(filter, Qt::CaseInsensitive)) {
            records.append(record);
        }
    }

    return records;
}

void MainWindow::updateStatus() {
    statusBar()->showMessage(
        QString("Loaded logs: %1 | Packets: %2 | Visible: %3 | Estimated alerts: %4 | Simulator: %5 shown, %6 queued | Packet replay: %7 shown, %8 queued | File: %9")
            .arg(logs.size())
            .arg(packetRecords.size())
            .arg(logTable ? logTable->rowCount() : 0)
            .arg(alertCount())
            .arg(simulationMode ? simulatedRecords.size() : 0)
            .arg(simulationMode ? static_cast<int>(simulationQueue.size()) : 0)
            .arg(packetReplayMode ? displayedPackets.size() : 0)
            .arg(packetReplayMode ? static_cast<int>(packetReplayQueue.size()) : 0)
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

void MainWindow::setSimulationControls(bool playing) {
    if (playButton) {
        playButton->setEnabled(!playing);
    }

    if (pauseButton) {
        pauseButton->setEnabled(playing);
    }
}

void MainWindow::clearSimulationQueue() {
    while (!simulationQueue.empty()) {
        simulationQueue.pop();
    }
}

void MainWindow::clearPacketReplayQueue() {
    while (!packetReplayQueue.empty()) {
        packetReplayQueue.pop();
    }
}

bool MainWindow::loadPacketsFromPcap(const QString &fileName, QString &errorMessage) {
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) {
        errorMessage = "Could not open the selected PCAP file.";
        return false;
    }

    QByteArray globalHeader = file.read(24);
    if (globalHeader.size() != 24) {
        errorMessage = "The PCAP global header is incomplete.";
        return false;
    }

    const uchar *magic = reinterpret_cast<const uchar *>(globalHeader.constData());
    bool littleEndian = false;
    if ((magic[0] == 0xd4 && magic[1] == 0xc3 && magic[2] == 0xb2 && magic[3] == 0xa1) ||
        (magic[0] == 0x4d && magic[1] == 0x3c && magic[2] == 0xb2 && magic[3] == 0xa1)) {
        littleEndian = true;
    } else if ((magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0xc3 && magic[3] == 0xd4) ||
               (magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0x3c && magic[3] == 0x4d)) {
        littleEndian = false;
    } else if (magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a) {
        errorMessage = "PCAPNG is not supported yet. Export the capture as classic .pcap first.";
        return false;
    } else {
        errorMessage = "Unsupported capture format or invalid PCAP magic number.";
        return false;
    }

    packetReplayTimer->stop();
    clearPacketReplayQueue();
    clearSimulationQueue();
    packetRecords.clear();
    displayedPackets.clear();
    simulatedRecords.clear();
    simulationMode = false;
    packetReplayMode = false;

    while (!file.atEnd()) {
        QByteArray packetHeader = file.read(16);
        if (packetHeader.isEmpty()) {
            break;
        }
        if (packetHeader.size() != 16) {
            errorMessage = "Encountered a truncated packet header.";
            return false;
        }

        std::uint32_t tsSec = readUInt32(packetHeader, 0, littleEndian);
        std::uint32_t inclLen = readUInt32(packetHeader, 8, littleEndian);
        QByteArray frame = file.read(static_cast<qint64>(inclLen));
        if (frame.size() != static_cast<int>(inclLen)) {
            errorMessage = "Encountered a truncated packet payload.";
            return false;
        }

        if (frame.size() < 14) {
            continue;
        }

        const uchar *raw = reinterpret_cast<const uchar *>(frame.constData());
        std::uint16_t etherType = (static_cast<std::uint16_t>(raw[12]) << 8) | raw[13];
        int networkOffset = 14;
        if (etherType == 0x8100 && frame.size() >= 18) {
            etherType = (static_cast<std::uint16_t>(raw[16]) << 8) | raw[17];
            networkOffset = 18;
        }
        if (etherType != 0x0800 || frame.size() < networkOffset + 20) {
            continue;
        }

        const uchar *ip = raw + networkOffset;
        int version = ip[0] >> 4;
        int ihl = (ip[0] & 0x0f) * 4;
        if (version != 4 || ihl < 20 || frame.size() < networkOffset + ihl) {
            continue;
        }

        int totalLength = (static_cast<int>(ip[2]) << 8) | ip[3];
        int protocol = ip[9];
        QString srcIP = ipv4ToString(ip + 12);
        QString dstIP = ipv4ToString(ip + 16);
        int transportOffset = networkOffset + ihl;
        int srcPort = 0;
        int dstPort = 0;
        QString protocolName = QString("IP-%1").arg(protocol);
        QString info = "IPv4 packet";

        if (protocol == 6 && frame.size() >= transportOffset + 20) {
            const uchar *tcp = raw + transportOffset;
            srcPort = (static_cast<int>(tcp[0]) << 8) | tcp[1];
            dstPort = (static_cast<int>(tcp[2]) << 8) | tcp[3];
            int flags = tcp[13];
            QStringList flagNames;
            if (flags & 0x02) flagNames << "SYN";
            if (flags & 0x10) flagNames << "ACK";
            if (flags & 0x01) flagNames << "FIN";
            if (flags & 0x04) flagNames << "RST";
            if (flags & 0x08) flagNames << "PSH";
            if (flags & 0x20) flagNames << "URG";
            protocolName = "TCP";
            info = QString("%1 -> %2 %3").arg(srcPort).arg(dstPort).arg(flagNames.join(","));
        } else if (protocol == 17 && frame.size() >= transportOffset + 8) {
            const uchar *udp = raw + transportOffset;
            srcPort = (static_cast<int>(udp[0]) << 8) | udp[1];
            dstPort = (static_cast<int>(udp[2]) << 8) | udp[3];
            protocolName = "UDP";
            info = QString("%1 -> %2").arg(srcPort).arg(dstPort);
        } else if (protocol == 1 && frame.size() >= transportOffset + 4) {
            const uchar *icmp = raw + transportOffset;
            protocolName = "ICMP";
            info = QString("Type %1 Code %2").arg(icmp[0]).arg(icmp[1]);
        }

        packetRecords.append({
            static_cast<long>(tsSec),
            srcIP,
            dstIP,
            srcPort,
            dstPort,
            protocolName,
            totalLength > 0 ? totalLength : static_cast<int>(inclLen),
            info
        });
    }

    if (packetRecords.isEmpty()) {
        errorMessage = "No supported IPv4 packets were found in this PCAP.";
        return false;
    }

    std::sort(packetRecords.begin(), packetRecords.end(), [](const PacketRecord &left, const PacketRecord &right) {
        return left.timestamp < right.timestamp;
    });

    return true;
}

void MainWindow::rebuildLogsFromPackets() {
    logs.clear();

    std::unordered_map<std::string, int> counts;
    std::unordered_map<std::string, long> firstSeen;
    std::unordered_map<std::string, int> synCounts;
    std::unordered_map<std::string, std::unordered_set<int>> uniquePortsByIP;

    for (const PacketRecord &packet : packetRecords) {
        if (packet.dstPort <= 0) {
            continue;
        }

        std::string srcIP = packet.srcIP.toStdString();
        std::string key = srcIP + "|" + std::to_string(packet.dstPort);
        counts[key]++;
        uniquePortsByIP[srcIP].insert(packet.dstPort);

        if (!firstSeen.count(key) || packet.timestamp < firstSeen[key]) {
            firstSeen[key] = packet.timestamp;
        }

        if (packet.protocol == "TCP" && packet.info.contains("SYN", Qt::CaseInsensitive) &&
            !packet.info.contains("ACK", Qt::CaseInsensitive)) {
            synCounts[key]++;
        }
    }

    for (const auto &entry : counts) {
        const std::string &key = entry.first;
        size_t separator = key.find('|');
        std::string srcIP = key.substr(0, separator);
        int dstPort = std::stoi(key.substr(separator + 1));
        int count = entry.second;
        std::string attackType = "NORMAL";

        if (LoginPorts.count(dstPort) && synCounts[key] >= 5) {
            attackType = "FAILED_LOGIN";
        } else if (uniquePortsByIP[srcIP].size() >= 3) {
            attackType = "PORT_SCAN";
        }

        logs.insertLog(srcIP, dstPort, count, attackType, firstSeen[key]);
    }
}

void MainWindow::showPacketMode() {
    packetMode = true;
    packetReplayMode = false;
    simulationMode = false;
    populatePacketTable(packetRecords);
    updateStatus();
}

std::uint32_t MainWindow::readUInt32(const QByteArray &bytes, int offset, bool littleEndian) const {
    const uchar *raw = reinterpret_cast<const uchar *>(bytes.constData() + offset);
    if (littleEndian) {
        return static_cast<std::uint32_t>(raw[0]) |
               (static_cast<std::uint32_t>(raw[1]) << 8) |
               (static_cast<std::uint32_t>(raw[2]) << 16) |
               (static_cast<std::uint32_t>(raw[3]) << 24);
    }

    return (static_cast<std::uint32_t>(raw[0]) << 24) |
           (static_cast<std::uint32_t>(raw[1]) << 16) |
           (static_cast<std::uint32_t>(raw[2]) << 8) |
           static_cast<std::uint32_t>(raw[3]);
}

QString MainWindow::ipv4ToString(const uchar *bytes) const {
    return QString("%1.%2.%3.%4")
        .arg(bytes[0])
        .arg(bytes[1])
        .arg(bytes[2])
        .arg(bytes[3]);
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
