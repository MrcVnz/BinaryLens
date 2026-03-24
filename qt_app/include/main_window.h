#pragma once

#include <QMainWindow>
#include <QString>

class QLabel;
class QLineEdit;
class QPushButton;
class QTextEdit;
class QProgressBar;
class QThread;
class AnalysisWorker;

// main desktop shell for the qt frontend.
// fixed-size product-style shell for BinaryLens using Qt Widgets.
class MainWindow final : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private slots:
    void browseForFile();
    void startAnalysis();
    void cancelAnalysis();
    void exportReport();
    void copyReport();
    void exportIocs();
    void toggleViewMode();
    void toggleTheme();
    void openCreatorGithub();

    void onProgressChanged(int percent, const QString& statusLine);
    void onAnalysisCompleted(const QString& visibleReport,
        const QString& standardReport,
        const QString& analystReport,
        const QString& iocReport,
        const QString& jsonReport);
    void onAnalysisFailed(const QString& errorText);
    void onAnalysisCancelled();

private:
    void buildUi();
    void applyTheme();
    void updateActionState();
    void updateTargetModeHint();
    void clearSelectedFileState();
    void refreshSelectedFileLabel();
    bool isBareIpv4Target(const QString& text) const;
    bool isBareIpv6Target(const QString& text) const;
    bool isLikelyHostTarget(const QString& text) const;
    bool isUrlTarget() const;
    QString normalizedAnalysisTarget() const;
    QString activeReport() const;
    void setStatusText(const QString& text);
    bool writeUtf8File(const QString& path, const QString& text);

    QWidget* m_central = nullptr;
    QLabel* m_headerTitle = nullptr;
    QLabel* m_headerSubtitle = nullptr;
    QLabel* m_targetLabel = nullptr;
    QLineEdit* m_targetInput = nullptr;
    QLabel* m_selectedFileLabel = nullptr;
    QPushButton* m_selectFileButton = nullptr;
    QPushButton* m_analyzeButton = nullptr;
    QPushButton* m_cancelButton = nullptr;
    QPushButton* m_exportButton = nullptr;
    QPushButton* m_copyButton = nullptr;
    QPushButton* m_viewToggleButton = nullptr;
    QPushButton* m_exportIocButton = nullptr;
    QPushButton* m_themeButton = nullptr;
    QPushButton* m_githubCreatorButton = nullptr;
    QTextEdit* m_resultsBox = nullptr;
    QProgressBar* m_progressBar = nullptr;
    QLabel* m_statusLabel = nullptr;

    QThread* m_workerThread = nullptr;
    AnalysisWorker* m_worker = nullptr;

    QString m_selectedFilePath;
    QString m_standardReport;
    QString m_analystReport;
    QString m_iocReport;
    QString m_jsonReport;
    bool m_darkTheme = true;
    bool m_analystView = false;
    bool m_analysisRunning = false;
};