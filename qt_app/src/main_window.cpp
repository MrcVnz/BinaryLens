
#include "main_window.h"

#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFileDialog>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QTextEdit>
#include <QThread>
#include <QVBoxLayout>
#include <QStyle>

#include "analysis_worker.h"

namespace
{
    constexpr int kWindowWidth = 1200;
    constexpr int kWindowHeight = 840;

    void ApplyShadow(QWidget* widget, const QColor& color, int blurRadius, int yOffset)
    {
        if (!widget)
            return;

        auto* effect = new QGraphicsDropShadowEffect(widget);
        effect->setBlurRadius(blurRadius);
        effect->setOffset(0, yOffset);
        effect->setColor(color);
        widget->setGraphicsEffect(effect);
    }

    // keep the whole visual system in one stylesheet builder so theme diffs stay centralized.
    QString BuildStyleSheet(bool darkTheme)
    {
        if (darkTheme)
        {
            return QStringLiteral(R"(
                QMainWindow, QWidget#root {
                    background: #0b1220;
                    color: #e5eefb;
                    font-family: "Segoe UI Variable Display", "Segoe UI", sans-serif;
                    font-size: 13px;
                }
                QWidget#topBar {
                    background: transparent;
                    border: none;
                }
                QWidget#titleShell {
                    background: transparent;
                    border: none;
                }
                QFrame[card="true"] {
                    background: #101a2b;
                    border: 1px solid #223452;
                    border-radius: 22px;
                }
                QLabel#headerTitle {
                    font-size: 34px;
                    font-weight: 800;
                    color: #f7fbff;
                    letter-spacing: 0.3px;
                }
                QLabel#mutedLabel {
                    color: #95a6c3;
                    font-size: 13px;
                }
                QLabel#sectionLabel {
                    font-size: 14px;
                    font-weight: 700;
                    color: #e6effc;
                }
                QLabel#statusCapsule {
                    background: rgba(15, 23, 38, 0.85);
                    border: 1px solid #20324e;
                    border-radius: 10px;
                    padding: 6px 10px;
                    color: #9bb0ce;
                }
                QLineEdit {
                    min-height: 52px;
                    background: #08101d;
                    border: 1px solid #2b4367;
                    border-radius: 15px;
                    padding: 0 16px;
                    color: #edf4ff;
                    selection-background-color: #3b82f6;
                    font-size: 13px;
                }
                QLineEdit:hover {
                    border: 1px solid #42648f;
                    background: #0a1322;
                }
                QLineEdit:focus {
                    border: 1px solid #60a5fa;
                    background: #0b1423;
                }
                QTextEdit {
                    background: #050b14;
                    border: 1px solid #233552;
                    border-radius: 18px;
                    padding: 14px;
                    color: #e7eef9;
                    font-family: "Cascadia Mono", "Consolas", monospace;
                    font-size: 12px;
                }
                QTextEdit:hover {
                    border-color: #2b4470;
                }
                QProgressBar {
                    min-height: 12px;
                    max-height: 12px;
                    border: 0;
                    border-radius: 6px;
                    background: #162338;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background: #3b82f6;
                    border-radius: 6px;
                }
                QPushButton {
                    min-height: 44px;
                    border-radius: 14px;
                    border: 1px solid #29415f;
                    background: #152238;
                    color: #eff5ff;
                    font-weight: 700;
                    padding: 0 16px;
                }
                QPushButton:hover {
                    background: #1b2b46;
                    border-color: #4f77a9;
                }
                QPushButton:pressed {
                    background: #142238;
                    padding-top: 1px;
                }
                QPushButton:disabled {
                    background: #0f1726;
                    color: #657790;
                    border-color: #1a2a42;
                }
                QPushButton#themeButton {
                    min-width: 140px;
                    min-height: 42px;
                    border-radius: 16px;
                    background: #12233b;
                    border: 1px solid #35527a;
                }
                QPushButton#themeButton:hover {
                    background: #17304f;
                    border-color: #4b74ab;
                }
                QPushButton[role="primary"] {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                stop:0 #2563eb, stop:1 #3b82f6);
                    border-color: #3b82f6;
                }
                QPushButton[role="primary"]:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                stop:0 #2d6cf0, stop:1 #4a8cf7);
                    border-color: #6aa6ff;
                }
                QPushButton[role="danger"] {
                    background: #2b1820;
                    border-color: #5a2635;
                    color: #ffd6de;
                }
                QPushButton[role="danger"]:hover {
                    background: #3a1e28;
                    border-color: #7c3248;
                }
            )");
        }

        return QStringLiteral(R"(
            QMainWindow, QWidget#root {
                background: #e8ecf1;
                color: #1a2430;
                font-family: "Segoe UI Variable Display", "Segoe UI", sans-serif;
                font-size: 13px;
            }
            QWidget#topBar {
                background: transparent;
                border: none;
            }
            QWidget#titleShell {
                background: transparent;
                border: none;
            }
            QFrame[card="true"] {
                background: #f5f7fa;
                border: 1px solid #c9d1db;
                border-radius: 22px;
            }
            QLabel#headerTitle {
                font-size: 34px;
                font-weight: 800;
                color: #16202c;
                letter-spacing: 0.3px;
            }
            QLabel#mutedLabel {
                color: #5f6d7c;
                font-size: 13px;
            }
            QLabel#sectionLabel {
                font-size: 14px;
                font-weight: 700;
                color: #273444;
            }
            QLabel#statusCapsule {
                background: #eef2f6;
                border: 1px solid #d2d9e1;
                border-radius: 10px;
                padding: 6px 10px;
                color: #5b6878;
            }
            QLineEdit {
                min-height: 52px;
                background: #f1f4f8;
                border: 1px solid #c5ced8;
                border-radius: 15px;
                padding: 0 16px;
                color: #172231;
                selection-background-color: #3b82f6;
                font-size: 13px;
            }
            QLineEdit:hover {
                border: 1px solid #9babc0;
                background: #f6f8fb;
            }
            QLineEdit:focus {
                border: 1px solid #4b86e5;
                background: #fbfcfe;
            }
            QTextEdit {
                background: #f3f6f9;
                border: 1px solid #cfd7e0;
                border-radius: 18px;
                padding: 14px;
                color: #182534;
                font-family: "Cascadia Mono", "Consolas", monospace;
                font-size: 12px;
            }
            QTextEdit:hover {
                border-color: #afbbc9;
            }
            QProgressBar {
                min-height: 12px;
                max-height: 12px;
                border: 0;
                border-radius: 6px;
                background: #d8e0e8;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #3b6fd8;
                border-radius: 6px;
            }
            QPushButton {
                min-height: 44px;
                border-radius: 14px;
                border: 1px solid #c2ccd6;
                background: #eceff3;
                color: #1d2a39;
                font-weight: 700;
                padding: 0 16px;
            }
            QPushButton:hover {
                background: #f6f8fb;
                border-color: #95a8bd;
            }
            QPushButton:pressed {
                background: #e2e7ed;
                padding-top: 1px;
            }
            QPushButton:disabled {
                background: #e4e8ed;
                color: #8391a0;
                border-color: #d1d8e0;
            }
            QPushButton#themeButton {
                min-width: 140px;
                min-height: 42px;
                border-radius: 16px;
                background: #eceff3;
                border: 1px solid #c6cfd8;
            }
            QPushButton#themeButton:hover {
                background: #f6f8fb;
                border-color: #9db0c4;
            }
            QPushButton[role="primary"] {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 #3269d5, stop:1 #4d83eb);
                border-color: #336fdd;
                color: #ffffff;
            }
            QPushButton[role="primary"]:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 #3b74df, stop:1 #5a8ff0);
                border-color: #598ee9;
            }
            QPushButton[role="danger"] {
                background: #f4ebee;
                border-color: #d2b4be;
                color: #7a2d3d;
            }
            QPushButton[role="danger"]:hover {
                background: #f7e3e8;
                border-color: #caa0ad;
            }
        )");
    }
}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    buildUi();
    applyTheme();
    updateActionState();
}

MainWindow::~MainWindow()
{
    if (m_workerThread)
    {
        m_workerThread->quit();
        m_workerThread->wait();
    }
}

// build the widget tree once, then theme it through stylesheet swaps.
void MainWindow::buildUi()
{
    setWindowTitle(QStringLiteral("BinaryLens"));
    setFixedSize(kWindowWidth, kWindowHeight);
    setWindowFlags((windowFlags() | Qt::CustomizeWindowHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint | Qt::WindowMinimizeButtonHint) & ~Qt::WindowMaximizeButtonHint);

    m_central = new QWidget(this);
    m_central->setObjectName(QStringLiteral("root"));
    setCentralWidget(m_central);

    // the qt shell follows the same flow as the win32 ui: target card, actions, results.
    auto* rootLayout = new QVBoxLayout(m_central);
    rootLayout->setContentsMargins(24, 22, 24, 24);
    rootLayout->setSpacing(18);

    auto* topBar = new QWidget(m_central);
    topBar->setObjectName(QStringLiteral("topBar"));
    auto* topBarLayout = new QHBoxLayout(topBar);
    topBarLayout->setContentsMargins(0, 0, 0, 0);
    topBarLayout->setSpacing(12);

    auto* leftSpacer = new QWidget(topBar);
    leftSpacer->setFixedWidth(148);

    auto* titleShell = new QWidget(topBar);
    titleShell->setObjectName(QStringLiteral("titleShell"));
    auto* titleLayout = new QVBoxLayout(titleShell);
    titleLayout->setContentsMargins(0, 0, 0, 0);
    titleLayout->setSpacing(0);

    m_headerTitle = new QLabel(QStringLiteral("BinaryLens"), titleShell);
    m_headerTitle->setObjectName(QStringLiteral("headerTitle"));
    m_headerTitle->setAlignment(Qt::AlignCenter);
    titleLayout->addWidget(m_headerTitle);

    m_headerSubtitle = nullptr;

    m_themeButton = new QPushButton(QStringLiteral("Light Theme"), topBar);
    m_themeButton->setObjectName(QStringLiteral("themeButton"));
    m_themeButton->setCursor(Qt::PointingHandCursor);
    m_themeButton->setMinimumWidth(140);
    connect(m_themeButton, &QPushButton::clicked, this, &MainWindow::toggleTheme);

    topBarLayout->addWidget(leftSpacer, 0, Qt::AlignVCenter);
    topBarLayout->addStretch(1);
    topBarLayout->addWidget(titleShell, 0, Qt::AlignCenter);
    topBarLayout->addStretch(1);
    topBarLayout->addWidget(m_themeButton, 0, Qt::AlignVCenter);
    rootLayout->addWidget(topBar);

    auto* targetCard = new QFrame(m_central);
    targetCard->setProperty("card", true);
    ApplyShadow(targetCard, m_darkTheme ? QColor(0, 0, 0, 75) : QColor(32, 74, 122, 26), 34, 10);

    auto* targetLayout = new QVBoxLayout(targetCard);
    targetLayout->setContentsMargins(20, 18, 20, 18);
    targetLayout->setSpacing(12);

    m_targetLabel = new QLabel(QStringLiteral("Target"), targetCard);
    m_targetLabel->setObjectName(QStringLiteral("sectionLabel"));
    targetLayout->addWidget(m_targetLabel);

    auto* targetInputRow = new QHBoxLayout();
    targetInputRow->setSpacing(12);

    m_targetInput = new QLineEdit(targetCard);
    m_targetInput->setPlaceholderText(QStringLiteral("Paste a file path or URL to analyze"));
    connect(m_targetInput, &QLineEdit::textEdited, this, [this](const QString& text) {
        if (!m_selectedFilePath.isEmpty() && text != m_selectedFilePath)
            clearSelectedFileState();
        updateTargetModeHint();
    });
    connect(m_targetInput, &QLineEdit::textChanged, this, [this](const QString&) {
        updateTargetModeHint();
    });

    m_selectFileButton = new QPushButton(QStringLiteral("Select File"), targetCard);
    m_selectFileButton->setProperty("role", "primary");
    m_selectFileButton->setCursor(Qt::PointingHandCursor);
    m_selectFileButton->style()->unpolish(m_selectFileButton);
    m_selectFileButton->style()->polish(m_selectFileButton);
    m_selectFileButton->setMinimumWidth(168);
    ApplyShadow(m_selectFileButton, m_darkTheme ? QColor(37, 99, 235, 30) : QColor(37, 99, 235, 28), 18, 6);
    connect(m_selectFileButton, &QPushButton::clicked, this, &MainWindow::browseForFile);

    targetInputRow->addWidget(m_targetInput, 1);
    targetInputRow->addWidget(m_selectFileButton);
    targetLayout->addLayout(targetInputRow);

    m_selectedFileLabel = new QLabel(QStringLiteral("No file selected"), targetCard);
    m_selectedFileLabel->setObjectName(QStringLiteral("statusCapsule"));
    targetLayout->addWidget(m_selectedFileLabel);

    auto* actionRow = new QHBoxLayout();
    actionRow->setSpacing(12);

    m_analyzeButton = new QPushButton(QStringLiteral("Analyze"), targetCard);
    m_analyzeButton->setProperty("role", "primary");
    m_analyzeButton->setCursor(Qt::PointingHandCursor);

    m_cancelButton = new QPushButton(QStringLiteral("Cancel"), targetCard);
    m_cancelButton->setProperty("role", "danger");
    m_cancelButton->setCursor(Qt::PointingHandCursor);

    m_exportButton = new QPushButton(QStringLiteral("Export Report"), targetCard);
    m_exportButton->setCursor(Qt::PointingHandCursor);

    m_copyButton = new QPushButton(QStringLiteral("Copy Report"), targetCard);
    m_copyButton->setCursor(Qt::PointingHandCursor);

    m_viewToggleButton = new QPushButton(QStringLiteral("Analyst View"), targetCard);
    m_viewToggleButton->setCursor(Qt::PointingHandCursor);

    m_exportIocButton = new QPushButton(QStringLiteral("Export IOCs"), targetCard);
    m_exportIocButton->setCursor(Qt::PointingHandCursor);

    for (QPushButton* button : {m_analyzeButton, m_cancelButton, m_exportButton, m_copyButton, m_viewToggleButton, m_exportIocButton})
    {
        ApplyShadow(button, m_darkTheme ? QColor(0, 0, 0, 28) : QColor(20, 48, 80, 18), 18, 5);
    }

    connect(m_analyzeButton, &QPushButton::clicked, this, &MainWindow::startAnalysis);
    connect(m_cancelButton, &QPushButton::clicked, this, &MainWindow::cancelAnalysis);
    connect(m_exportButton, &QPushButton::clicked, this, &MainWindow::exportReport);
    connect(m_copyButton, &QPushButton::clicked, this, &MainWindow::copyReport);
    connect(m_viewToggleButton, &QPushButton::clicked, this, &MainWindow::toggleViewMode);
    connect(m_exportIocButton, &QPushButton::clicked, this, &MainWindow::exportIocs);

    actionRow->addWidget(m_analyzeButton);
    actionRow->addWidget(m_cancelButton);
    actionRow->addWidget(m_exportButton);
    actionRow->addWidget(m_copyButton);
    actionRow->addWidget(m_viewToggleButton);
    actionRow->addWidget(m_exportIocButton);
    targetLayout->addLayout(actionRow);

    rootLayout->addWidget(targetCard);

    auto* resultCard = new QFrame(m_central);
    resultCard->setProperty("card", true);
    ApplyShadow(resultCard, m_darkTheme ? QColor(0, 0, 0, 82) : QColor(32, 74, 122, 28), 38, 12);

    auto* resultLayout = new QVBoxLayout(resultCard);
    resultLayout->setContentsMargins(20, 18, 20, 18);
    resultLayout->setSpacing(12);

    auto* resultHeader = new QLabel(QStringLiteral("Results"), resultCard);
    resultHeader->setObjectName(QStringLiteral("sectionLabel"));
    resultLayout->addWidget(resultHeader);

    m_resultsBox = new QTextEdit(resultCard);
    m_resultsBox->setReadOnly(true);
    resultLayout->addWidget(m_resultsBox, 1);

    m_progressBar = new QProgressBar(resultCard);
    m_progressBar->setRange(0, 100);
    m_progressBar->setTextVisible(false);
    resultLayout->addWidget(m_progressBar);

    m_statusLabel = new QLabel(QStringLiteral("Ready"), resultCard);
    m_statusLabel->setObjectName(QStringLiteral("mutedLabel"));
    resultLayout->addWidget(m_statusLabel);

    rootLayout->addWidget(resultCard, 1);
}

// stylesheet swapping is enough because the widgets already carry the right object names.
void MainWindow::applyTheme()
{
    qApp->setStyleSheet(BuildStyleSheet(m_darkTheme));
    m_themeButton->setText(m_darkTheme ? QStringLiteral("Light Theme") : QStringLiteral("Dark Theme"));
}

// action buttons mirror run state and the presence of generated report views.
void MainWindow::updateActionState()
{
    const bool hasReport = !m_standardReport.isEmpty();
    m_analyzeButton->setEnabled(!m_analysisRunning);
    m_cancelButton->setEnabled(m_analysisRunning);
    m_selectFileButton->setEnabled(!m_analysisRunning);
    m_targetInput->setEnabled(!m_analysisRunning);
    m_exportButton->setEnabled(hasReport && !m_analysisRunning);
    m_copyButton->setEnabled(hasReport && !m_analysisRunning);
    m_viewToggleButton->setEnabled((!m_analystReport.isEmpty()) && !m_analysisRunning);
    m_exportIocButton->setEnabled((!m_iocReport.isEmpty()) && !m_analysisRunning);
    m_viewToggleButton->setText(m_analystView ? QStringLiteral("User View") : QStringLiteral("Analyst View"));
}

void MainWindow::clearSelectedFileState()
{
    m_selectedFilePath.clear();
    refreshSelectedFileLabel();
}

void MainWindow::refreshSelectedFileLabel()
{
    if (m_selectedFilePath.isEmpty())
    {
        m_selectedFileLabel->setText(QStringLiteral("No file selected"));
        return;
    }

    m_selectedFileLabel->setText(QStringLiteral("Selected file: %1").arg(m_selectedFilePath));
}

// typing a url automatically clears the remembered file target to avoid mixed-mode runs.
void MainWindow::updateTargetModeHint()
{
    const QString trimmed = m_targetInput->text().trimmed();

    if (!m_selectedFilePath.isEmpty())
    {
        if (trimmed == m_selectedFilePath)
        {
            refreshSelectedFileLabel();
            return;
        }

        clearSelectedFileState();
    }

    if (trimmed.isEmpty())
    {
        m_selectedFileLabel->setText(QStringLiteral("No file selected"));
        return;
    }

    m_selectedFileLabel->setText(isUrlTarget()
        ? QStringLiteral("URL/IP mode detected from the current target")
        : QStringLiteral("File path mode detected from the current target"));
}

bool MainWindow::isUrlTarget() const
{
    const QString value = m_targetInput->text().trimmed().toLower();
    return value.startsWith(QStringLiteral("http://")) || value.startsWith(QStringLiteral("https://"));
}

QString MainWindow::activeReport() const
{
    if (m_analystView && !m_analystReport.isEmpty())
        return m_analystReport;
    return m_standardReport;
}

void MainWindow::setStatusText(const QString& text)
{
    m_statusLabel->setText(text);
}

bool MainWindow::writeUtf8File(const QString& path, const QString& text)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        return false;
    file.write(text.toUtf8());
    return file.error() == QFileDevice::NoError;
}

void MainWindow::browseForFile()
{
    const QString filePath = QFileDialog::getOpenFileName(this, QStringLiteral("Select file to analyze"));
    if (filePath.isEmpty())
        return;

    m_selectedFilePath = filePath;
    m_targetInput->setText(filePath);
    refreshSelectedFileLabel();
}

// spin the worker into its own thread so large scans never block repaint or input.
// snapshot the current target before the worker thread starts.
void MainWindow::startAnalysis()
{
    const QString target = m_targetInput->text().trimmed();
    if (target.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("BinaryLens"), QStringLiteral("Choose a file or paste a URL first."));
        return;
    }

    m_standardReport.clear();
    m_analystReport.clear();
    m_iocReport.clear();
    m_jsonReport.clear();
    m_resultsBox->clear();
    m_progressBar->setValue(0);
    setStatusText(QStringLiteral("Starting analysis..."));
    m_analysisRunning = true;
    updateActionState();

    m_workerThread = new QThread(this);
    m_worker = new AnalysisWorker();
    m_worker->moveToThread(m_workerThread);

    connect(m_workerThread, &QThread::started, this, [this, target]() {
        m_worker->runAnalysis(target, isUrlTarget(), m_analystView);
    });
    connect(m_worker, &AnalysisWorker::progressChanged, this, &MainWindow::onProgressChanged);
    // completion, failure, and cancel all tear the thread down through the same cleanup path.
    connect(m_worker, &AnalysisWorker::analysisCompleted, this, &MainWindow::onAnalysisCompleted);
    connect(m_worker, &AnalysisWorker::analysisFailed, this, &MainWindow::onAnalysisFailed);
    connect(m_worker, &AnalysisWorker::cancelled, this, &MainWindow::onAnalysisCancelled);
    connect(m_worker, &AnalysisWorker::analysisCompleted, m_workerThread, &QThread::quit);
    connect(m_worker, &AnalysisWorker::analysisFailed, m_workerThread, &QThread::quit);
    connect(m_worker, &AnalysisWorker::cancelled, m_workerThread, &QThread::quit);
    connect(m_workerThread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(m_workerThread, &QThread::finished, m_workerThread, &QObject::deleteLater);
    connect(m_workerThread, &QThread::finished, this, [this]() {
        m_worker = nullptr;
        m_workerThread = nullptr;
    });

    m_workerThread->start();
}

void MainWindow::cancelAnalysis()
{
    if (m_worker)
        m_worker->cancel();
    setStatusText(QStringLiteral("Cancellation requested..."));
}

void MainWindow::exportReport()
{
    if (m_standardReport.isEmpty())
        return;

    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Export report"), QStringLiteral("BinaryLens_Report.txt"), QStringLiteral("Text Report (*.txt)"));
    if (path.isEmpty())
        return;

    if (!writeUtf8File(path, activeReport()))
        QMessageBox::critical(this, QStringLiteral("BinaryLens"), QStringLiteral("Could not save the report to the selected location."));
}

void MainWindow::copyReport()
{
    if (m_standardReport.isEmpty())
        return;
    QApplication::clipboard()->setText(activeReport());
    setStatusText(QStringLiteral("Report copied to clipboard"));
}

void MainWindow::exportIocs()
{
    if (m_iocReport.isEmpty())
        return;

    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Export IOCs"), QStringLiteral("BinaryLens_IOCs.txt"), QStringLiteral("Text Report (*.txt)"));
    if (path.isEmpty())
        return;

    if (!writeUtf8File(path, m_iocReport))
        QMessageBox::critical(this, QStringLiteral("BinaryLens"), QStringLiteral("Could not save the IOC export to the selected location."));
}

void MainWindow::toggleViewMode()
{
    if (m_analystReport.isEmpty())
        return;
    m_analystView = !m_analystView;
    m_resultsBox->setPlainText(activeReport());
    updateActionState();
}

void MainWindow::toggleTheme()
{
    m_darkTheme = !m_darkTheme;
    applyTheme();
}

void MainWindow::onProgressChanged(int percent, const QString& statusLine)
{
    m_progressBar->setValue(percent);
    if (!statusLine.isEmpty())
        setStatusText(statusLine);
}

// keep every report variant in memory so toggles and exports are instant.
// ui state is restored here in one place to avoid partial reset paths.
void MainWindow::onAnalysisCompleted(const QString& visibleReport,
                                     const QString& standardReport,
                                     const QString& analystReport,
                                     const QString& iocReport,
                                     const QString& jsonReport)
{
    m_standardReport = standardReport;
    m_analystReport = analystReport;
    m_iocReport = iocReport;
    m_jsonReport = jsonReport;
    m_resultsBox->setPlainText(visibleReport);
    m_progressBar->setValue(100);

    m_targetInput->clear();
    clearSelectedFileState();
    updateTargetModeHint();

    setStatusText(QStringLiteral("Analysis complete"));
    m_analysisRunning = false;
    updateActionState();
}

void MainWindow::onAnalysisFailed(const QString& errorText)
{
    m_analysisRunning = false;
    updateActionState();
    m_progressBar->setValue(0);
    setStatusText(QStringLiteral("Analysis failed"));
    QMessageBox::critical(this, QStringLiteral("BinaryLens"), errorText);
}

void MainWindow::onAnalysisCancelled()
{
    m_targetInput->clear();
    clearSelectedFileState();
    updateTargetModeHint();

    m_analysisRunning = false;
    updateActionState();
    m_progressBar->setValue(0);
    setStatusText(QStringLiteral("Analysis cancelled"));
}
