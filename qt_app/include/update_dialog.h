#pragma once

#include <QDialog>
#include <QStringList>

#include "update_checker.h"

class QCloseEvent;
class QLabel;
class QPushButton;
class QTextBrowser;

// themed in-app release prompt that keeps update actions inside the product experience.
class UpdateDialog final : public QDialog
{
    Q_OBJECT
public:
    explicit UpdateDialog(const UpdateCheckResult& result, bool darkTheme, QWidget* parent = nullptr);

    void setDarkTheme(bool darkTheme);
    QString version() const;

signals:
    void ignoreVersionRequested(const QString& version);
    void remindLaterRequested(int hours);

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void openInstallerDownload();
    void openPortableDownload();
    void openReleasePage();
    void ignoreThisVersion();
    void remindLater();

private:
    void buildUi();
    void applyTheme();
    ReleaseAssetInfo bestAssetMatch(const QStringList& needles) const;
    QString summarizePublishedDate() const;
    void openAssetOrFallback(const ReleaseAssetInfo& asset) const;

    UpdateCheckResult m_result;
    bool m_darkTheme = true;
    bool m_decisionMade = false;

    QLabel* m_titleLabel = nullptr;
    QLabel* m_summaryLabel = nullptr;
    QLabel* m_versionCapsule = nullptr;
    QLabel* m_releaseDateLabel = nullptr;
    QTextBrowser* m_notesBox = nullptr;
    QPushButton* m_installerButton = nullptr;
    QPushButton* m_portableButton = nullptr;
    QPushButton* m_releaseNotesButton = nullptr;
    QPushButton* m_ignoreButton = nullptr;
    QPushButton* m_laterButton = nullptr;
};
