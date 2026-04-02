#pragma once

#include <QDialog>
#include <QStringList>

#include "update_checker.h"

class QCloseEvent;
class QFile;
class QLabel;
class QNetworkAccessManager;
class QNetworkReply;
class QProgressBar;
class QPushButton;
class QTextBrowser;

// themed in-app release prompt that can download and apply updates without leaving the product.
class UpdateDialog final : public QDialog
{
    Q_OBJECT
public:
    explicit UpdateDialog(const UpdateCheckResult& result, bool darkTheme, QWidget* parent = nullptr);
    ~UpdateDialog() override;

    void setDarkTheme(bool darkTheme);
    QString version() const;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void startUpdateFlow();
    void openReleasePage();
    void remindLater();
    void cancelDownload();
    void onDownloadProgress(qint64 received, qint64 total);
    void onDownloadFinished();

private:
    enum class UpdateTarget
    {
        Installer,
        Portable
    };

    void buildUi();
    void applyTheme();
    void updateButtons();
    void setStatusText(const QString& text);
    ReleaseAssetInfo selectTargetAsset() const;
    bool isInstalledBuild() const;
    QString summarizePublishedDate() const;
    QString tempDownloadPathForAsset(const ReleaseAssetInfo& asset) const;
    bool beginDownload(const ReleaseAssetInfo& asset);
    bool launchUpdater(const ReleaseAssetInfo& asset, const QString& packagePath);

    UpdateCheckResult m_result;
    bool m_darkTheme = true;
    bool m_updateStarted = false;
    UpdateTarget m_target = UpdateTarget::Portable;

    QLabel* m_titleLabel = nullptr;
    QLabel* m_summaryLabel = nullptr;
    QLabel* m_versionCapsule = nullptr;
    QLabel* m_releaseDateLabel = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTextBrowser* m_notesBox = nullptr;
    QProgressBar* m_progressBar = nullptr;
    QPushButton* m_updateButton = nullptr;
    QPushButton* m_releaseNotesButton = nullptr;
    QPushButton* m_laterButton = nullptr;
    QPushButton* m_cancelButton = nullptr;

    QNetworkAccessManager* m_downloadManager = nullptr;
    QNetworkReply* m_downloadReply = nullptr;
    QFile* m_downloadFile = nullptr;
    ReleaseAssetInfo m_activeAsset;
};
