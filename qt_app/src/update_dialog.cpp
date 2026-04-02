#include "update_dialog.h"

#include <QCloseEvent>
#include <QDesktopServices>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextBrowser>
#include <QUrl>
#include <QVBoxLayout>

namespace
{
    QString BuildDialogStyle(bool darkTheme)
    {
        // mirror the app palette closely so the update prompt feels native to the product instead of a generic message box.
    if (darkTheme)
        {
            return QStringLiteral(R"(
                QDialog {
                    background: #0b1220;
                    color: #e8eef8;
                }
                QFrame#shell {
                    background: #111a2c;
                    border: 1px solid #243754;
                    border-radius: 22px;
                }
                QLabel#title {
                    font-size: 24px;
                    font-weight: 800;
                    color: #f7fbff;
                }
                QLabel#summary {
                    font-size: 13px;
                    color: #9bb0ce;
                }
                QLabel#capsule {
                    background: rgba(24, 39, 63, 0.9);
                    border: 1px solid #35527a;
                    border-radius: 11px;
                    padding: 7px 11px;
                    color: #cfe1ff;
                    font-weight: 700;
                }
                QTextBrowser {
                    background: #08101d;
                    border: 1px solid #243754;
                    border-radius: 16px;
                    padding: 12px;
                    color: #e6eef8;
                    font-family: "Cascadia Mono", "Consolas", monospace;
                    font-size: 12px;
                }
                QPushButton {
                    min-height: 42px;
                    border-radius: 14px;
                    border: 1px solid #2b4367;
                    background: #142238;
                    color: #edf4ff;
                    font-weight: 700;
                    padding: 0 16px;
                }
                QPushButton:hover {
                    background: #1a2b46;
                    border-color: #4c73a8;
                }
                QPushButton#primary {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                stop:0 #2563eb, stop:1 #3b82f6);
                    border-color: #3b82f6;
                }
                QPushButton#primary:hover {
                    border-color: #72acff;
                }
                QPushButton#subtle {
                    background: #101a2c;
                }
            )");
        }

        return QStringLiteral(R"(
            QDialog {
                background: #edf1f6;
                color: #1a2430;
            }
            QFrame#shell {
                background: #f7f9fc;
                border: 1px solid #ccd4de;
                border-radius: 22px;
            }
            QLabel#title {
                font-size: 24px;
                font-weight: 800;
                color: #16202c;
            }
            QLabel#summary {
                font-size: 13px;
                color: #607080;
            }
            QLabel#capsule {
                background: #eef2f6;
                border: 1px solid #cfd8e2;
                border-radius: 11px;
                padding: 7px 11px;
                color: #2d4054;
                font-weight: 700;
            }
            QTextBrowser {
                background: #f3f6fa;
                border: 1px solid #d1d9e2;
                border-radius: 16px;
                padding: 12px;
                color: #1b2734;
                font-family: "Cascadia Mono", "Consolas", monospace;
                font-size: 12px;
            }
            QPushButton {
                min-height: 42px;
                border-radius: 14px;
                border: 1px solid #c5ced8;
                background: #eceff3;
                color: #1d2a39;
                font-weight: 700;
                padding: 0 16px;
            }
            QPushButton:hover {
                background: #f6f8fb;
                border-color: #97abc0;
            }
            QPushButton#primary {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 #3369d6, stop:1 #4a82eb);
                border-color: #3d72db;
                color: #ffffff;
            }
            QPushButton#subtle {
                background: #f4f6f9;
            }
        )");
    }
}

UpdateDialog::UpdateDialog(const UpdateCheckResult& result, bool darkTheme, QWidget* parent)
    : QDialog(parent)
    , m_result(result)
    , m_darkTheme(darkTheme)
{
    buildUi();
    applyTheme();
}

void UpdateDialog::setDarkTheme(bool darkTheme)
{
    m_darkTheme = darkTheme;
    applyTheme();
}

QString UpdateDialog::version() const
{
    return m_result.release.version;
}

void UpdateDialog::closeEvent(QCloseEvent* event)
{
    if (!m_decisionMade)
        emit remindLaterRequested(24);
    QDialog::closeEvent(event);
}

void UpdateDialog::openInstallerDownload()
{
    m_decisionMade = true;
    openAssetOrFallback(bestAssetMatch({QStringLiteral("installer"), QStringLiteral("setup")}));
}

void UpdateDialog::openPortableDownload()
{
    m_decisionMade = true;
    openAssetOrFallback(bestAssetMatch({QStringLiteral("portable"), QStringLiteral("zip")}));
}

void UpdateDialog::openReleasePage()
{
    m_decisionMade = true;
    if (m_result.release.htmlUrl.isValid())
        QDesktopServices::openUrl(m_result.release.htmlUrl);
}

void UpdateDialog::ignoreThisVersion()
{
    m_decisionMade = true;
    emit ignoreVersionRequested(m_result.release.version);
    close();
}

void UpdateDialog::remindLater()
{
    m_decisionMade = true;
    emit remindLaterRequested(24);
    close();
}

void UpdateDialog::buildUi()
{
    setWindowTitle(QStringLiteral("BinaryLens Update Available"));
    setAttribute(Qt::WA_DeleteOnClose, true);
    setModal(false);
    resize(760, 560);

    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(16, 16, 16, 16);

    auto* shell = new QFrame(this);
    shell->setObjectName(QStringLiteral("shell"));
    auto* shellLayout = new QVBoxLayout(shell);
    shellLayout->setContentsMargins(22, 22, 22, 22);
    shellLayout->setSpacing(16);

    m_titleLabel = new QLabel(QStringLiteral("A new BinaryLens update is ready"), shell);
    m_titleLabel->setObjectName(QStringLiteral("title"));
    shellLayout->addWidget(m_titleLabel);

    m_summaryLabel = new QLabel(
        QStringLiteral("Version %1 is available. You are on %2.")
            .arg(m_result.release.version, m_result.release.currentVersion),
        shell);
    m_summaryLabel->setObjectName(QStringLiteral("summary"));
    m_summaryLabel->setWordWrap(true);
    shellLayout->addWidget(m_summaryLabel);

    auto* metaRow = new QHBoxLayout();
    metaRow->setSpacing(10);

    m_versionCapsule = new QLabel(QStringLiteral("latest %1").arg(m_result.release.tagName), shell);
    m_versionCapsule->setObjectName(QStringLiteral("capsule"));
    metaRow->addWidget(m_versionCapsule, 0, Qt::AlignLeft);

    m_releaseDateLabel = new QLabel(summarizePublishedDate(), shell);
    m_releaseDateLabel->setObjectName(QStringLiteral("capsule"));
    metaRow->addWidget(m_releaseDateLabel, 0, Qt::AlignLeft);
    metaRow->addStretch(1);
    shellLayout->addLayout(metaRow);

    // release notes stay embedded in the dialog so users can decide without leaving the app immediately.
    m_notesBox = new QTextBrowser(shell);
    m_notesBox->setOpenExternalLinks(true);
    m_notesBox->setReadOnly(true);
    const QString notes = m_result.release.body.trimmed().isEmpty()
        ? QStringLiteral("No release notes were published for this version.")
        : m_result.release.body.trimmed();
    m_notesBox->setPlainText(notes);
    shellLayout->addWidget(m_notesBox, 1);

    auto* actionRow = new QHBoxLayout();
    actionRow->setSpacing(10);

    m_installerButton = new QPushButton(QStringLiteral("Download Installer"), shell);
    m_installerButton->setObjectName(QStringLiteral("primary"));
    connect(m_installerButton, &QPushButton::clicked, this, &UpdateDialog::openInstallerDownload);

    m_portableButton = new QPushButton(QStringLiteral("Download Portable"), shell);
    m_portableButton->setObjectName(QStringLiteral("primary"));
    connect(m_portableButton, &QPushButton::clicked, this, &UpdateDialog::openPortableDownload);

    m_releaseNotesButton = new QPushButton(QStringLiteral("View Release Page"), shell);
    m_releaseNotesButton->setObjectName(QStringLiteral("subtle"));
    connect(m_releaseNotesButton, &QPushButton::clicked, this, &UpdateDialog::openReleasePage);

    m_ignoreButton = new QPushButton(QStringLiteral("Ignore This Version"), shell);
    m_ignoreButton->setObjectName(QStringLiteral("subtle"));
    connect(m_ignoreButton, &QPushButton::clicked, this, &UpdateDialog::ignoreThisVersion);

    m_laterButton = new QPushButton(QStringLiteral("Later"), shell);
    m_laterButton->setObjectName(QStringLiteral("subtle"));
    connect(m_laterButton, &QPushButton::clicked, this, &UpdateDialog::remindLater);

    m_installerButton->setEnabled(bestAssetMatch({QStringLiteral("installer"), QStringLiteral("setup")}).downloadUrl.isValid() || m_result.release.htmlUrl.isValid());
    m_portableButton->setEnabled(bestAssetMatch({QStringLiteral("portable"), QStringLiteral("zip")}).downloadUrl.isValid() || m_result.release.htmlUrl.isValid());

    actionRow->addWidget(m_installerButton);
    actionRow->addWidget(m_portableButton);
    actionRow->addWidget(m_releaseNotesButton);
    actionRow->addWidget(m_ignoreButton);
    actionRow->addWidget(m_laterButton);
    shellLayout->addLayout(actionRow);

    rootLayout->addWidget(shell);
}

void UpdateDialog::applyTheme()
{
    // a local stylesheet keeps the dialog stable even when the global app theme toggles later.
    setStyleSheet(BuildDialogStyle(m_darkTheme));
}

ReleaseAssetInfo UpdateDialog::bestAssetMatch(const QStringList& needles) const
{
    for (const ReleaseAssetInfo& asset : m_result.release.assets)
    {
        const QString lowerName = asset.name.toLower();
        bool allMatched = true;
        for (const QString& needle : needles)
        {
            if (!lowerName.contains(needle))
            {
                allMatched = false;
                break;
            }
        }
        if (allMatched)
            return asset;
    }

    for (const QString& needle : needles)
    {
        for (const ReleaseAssetInfo& asset : m_result.release.assets)
        {
            if (asset.name.toLower().contains(needle))
                return asset;
        }
    }

    return {};
}

QString UpdateDialog::summarizePublishedDate() const
{
    if (!m_result.release.publishedAt.isValid())
        return QStringLiteral("release date unavailable");
    return QStringLiteral("published %1").arg(m_result.release.publishedAt.toLocalTime().toString(QStringLiteral("dd MMM yyyy")));
}

void UpdateDialog::openAssetOrFallback(const ReleaseAssetInfo& asset) const
{
    if (asset.downloadUrl.isValid())
    {
        QDesktopServices::openUrl(asset.downloadUrl);
        return;
    }

    if (m_result.release.htmlUrl.isValid())
        QDesktopServices::openUrl(m_result.release.htmlUrl);
}
