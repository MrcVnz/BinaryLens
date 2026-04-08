#include "update_dialog.h"

#include <QCloseEvent>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProgressBar>
#include <QProcess>
#include <QPushButton>
#include <QStandardPaths>
#include <QTextBrowser>
#include <QUrl>
#include <QVBoxLayout>

namespace
{
    // style generation stays local so the dialog can mirror the app theme without depending on global stylesheet state.
    QString BuildDialogStyle(bool darkTheme)
    // builds this update dialog flow fragment in one place so the surrounding code can stay focused on flow.
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
                QLabel#status {
                    font-size: 12px;
                    color: #c7d6ee;
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
            QLabel#status {
                font-size: 12px;
                color: #425264;
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
            QProgressBar {
                min-height: 12px;
                max-height: 12px;
                border: 0;
                border-radius: 6px;
                background: #dde4eb;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #4a82eb;
                border-radius: 6px;
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

    // asset trust checks live here too because the dialog owns the download flow.
    bool IsTrustedGitHubHost(const QString& host)
    // answers this is trusted git hub host check in one place so the surrounding logic stays readable.
    {
        const QString normalized = host.trimmed().toLower();
        return normalized == QStringLiteral("github.com") ||
               normalized == QStringLiteral("objects.githubusercontent.com") ||
               normalized == QStringLiteral("release-assets.githubusercontent.com") ||
               normalized.endsWith(QStringLiteral(".githubusercontent.com"));
    }

    bool IsTrustedGitHubUrl(const QUrl& url)
    // answers this is trusted git hub url check in one place so the surrounding logic stays readable.
    {
        return url.isValid() && url.scheme() == QStringLiteral("https") && IsTrustedGitHubHost(url.host());
    }

    // argument quoting is kept simple because the updater only forwards controlled local paths.
    QString QuoteArgument(const QString& value)
    // keeps the quote argument step local to this update dialog flow file so callers can stay focused on intent.
    {
        QString escaped = value;
        escaped.replace(QLatin1Char('"'), QStringLiteral("\\\""));
        return QStringLiteral("\"") + escaped + QStringLiteral("\"");
    }
}

// construction does the minimum work needed to show the dialog quickly and safely.
UpdateDialog::UpdateDialog(const UpdateCheckResult& result, bool darkTheme, QWidget* parent)
    : QDialog(parent)
    , m_result(result)
    , m_darkTheme(darkTheme)
    , m_target(isInstalledBuild() ? UpdateTarget::Installer : UpdateTarget::Portable)
    , m_downloadManager(new QNetworkAccessManager(this))
// handles the update dialog ui work here so widget state changes do not leak across the file.
{
    buildUi();
    applyTheme();
}

UpdateDialog::~UpdateDialog()
// handles the destructor update dialog ui work here so widget state changes do not leak across the file.
{
    if (m_downloadReply)
        m_downloadReply->deleteLater();
    delete m_downloadFile;
}

void UpdateDialog::setDarkTheme(bool darkTheme)
// keeps the set dark theme step local to this update dialog flow file so callers can stay focused on intent.
{
    m_darkTheme = darkTheme;
    applyTheme();
}

QString UpdateDialog::version() const
// keeps the version step local to this update dialog flow file so callers can stay focused on intent.
{
    return m_result.release.version;
}

// closing is blocked while a package is streaming so the temp file state stays predictable.
void UpdateDialog::closeEvent(QCloseEvent* event)
// keeps the close event step local to this update dialog flow file so callers can stay focused on intent.
{
    if (m_downloadReply)
    {
        event->ignore();
        return;
    }

    QDialog::closeEvent(event);
}

// this starts the user-approved download path after the asset choice has been resolved.
void UpdateDialog::startUpdateFlow()
// handles the start update flow ui work here so widget state changes do not leak across the file.
{
    const ReleaseAssetInfo asset = selectTargetAsset();
    if (!asset.downloadUrl.isValid())
    {
        QMessageBox::warning(this,
            QStringLiteral("Update unavailable"),
            QStringLiteral("The expected update package could not be found in this release."));
        return;
    }

    beginDownload(asset);
}

// release notes can still be opened externally when the user wants more context than the embedded view.
void UpdateDialog::openReleasePage()
// keeps the open release page step local to this update dialog flow file so callers can stay focused on intent.
{
    if (m_result.release.htmlUrl.isValid())
        QDesktopServices::openUrl(m_result.release.htmlUrl);
}

// remind-later only closes the prompt; the caller owns when to ask again on a later launch.
void UpdateDialog::remindLater()
// keeps the remind later step local to this update dialog flow file so callers can stay focused on intent.
{
    if (m_downloadReply)
        return;

    close();
}

// cancellation tears down both the network reply and the temp file so retries start cleanly.
void UpdateDialog::cancelDownload()
// keeps the cancel download step local to this update dialog flow file so callers can stay focused on intent.
{
    if (!m_downloadReply)
        return;

    m_downloadReply->abort();
}

// progress text stays human-readable because this is a user-facing transfer, not a debug trace.
void UpdateDialog::onDownloadProgress(qint64 received, qint64 total)
// keeps the on download progress step local to this update dialog flow file so callers can stay focused on intent.
{
    if (total > 0)
    {
        const int percent = static_cast<int>((received * 100) / total);
        m_progressBar->setRange(0, 100);
        m_progressBar->setValue(percent);
        setStatusText(QStringLiteral("downloading %1 (%2% done)").arg(m_activeAsset.name).arg(percent));
        return;
    }

    m_progressBar->setRange(0, 0);
    setStatusText(QStringLiteral("downloading %1").arg(m_activeAsset.name));
}

// completion decides whether the helper should take over or whether the download result should be surfaced as an error.
void UpdateDialog::onDownloadFinished()
// keeps the on download finished step local to this update dialog flow file so callers can stay focused on intent.
{
    if (!m_downloadReply)
        return;

    QNetworkReply* reply = m_downloadReply;
    m_downloadReply = nullptr;

    if (reply && m_downloadFile)
        m_downloadFile->write(reply->readAll());

    if (m_downloadFile)
    {
        m_downloadFile->flush();
        m_downloadFile->close();
    }

    const QString packagePath = m_downloadFile ? m_downloadFile->fileName() : QString{};
    const bool aborted = reply->error() == QNetworkReply::OperationCanceledError;
    const QString errorText = reply->errorString();
    reply->deleteLater();

    if (aborted)
    {
        if (!packagePath.isEmpty())
            QFile::remove(packagePath);
        delete m_downloadFile;
        m_downloadFile = nullptr;
        m_activeAsset = {};
        m_updateStarted = false;
        m_progressBar->setRange(0, 100);
        m_progressBar->setValue(0);
        setStatusText(QStringLiteral("update download cancelled"));
        updateButtons();
        return;
    }

    if (!errorText.isEmpty() && errorText != QStringLiteral("Unknown error"))
    {
        if (!packagePath.isEmpty())
            QFile::remove(packagePath);
        delete m_downloadFile;
        m_downloadFile = nullptr;
        m_activeAsset = {};
        m_updateStarted = false;
        m_progressBar->setRange(0, 100);
        m_progressBar->setValue(0);
        setStatusText(QStringLiteral("update download failed"));
        updateButtons();
        QMessageBox::warning(this, QStringLiteral("Update failed"), errorText);
        return;
    }

    delete m_downloadFile;
    m_downloadFile = nullptr;

    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(100);
    setStatusText(QStringLiteral("download complete, preparing update..."));

    if (!launchUpdater(m_activeAsset, packagePath))
    {
        QFile::remove(packagePath);
        m_activeAsset = {};
        m_updateStarted = false;
        updateButtons();
        return;
    }

    // close the dialog and quit the app so the helper can replace files safely.
    accept();
    QCoreApplication::quit();
}

// widget construction is centralized so theme and state changes only have one tree to manage.
void UpdateDialog::buildUi()
// builds this update dialog flow fragment in one place so the surrounding code can stay focused on flow.
{
    setWindowTitle(QStringLiteral("BinaryLens Update Available"));
    setAttribute(Qt::WA_DeleteOnClose, true);
    setModal(false);
    resize(760, 600);

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

    const QString channelText = (m_target == UpdateTarget::Installer)
        ? QStringLiteral("installer build detected")
        : QStringLiteral("portable build detected");
    m_summaryLabel = new QLabel(
        QStringLiteral("Version %1 is available. You are on %2. %3.")
            .arg(m_result.release.version, m_result.release.currentVersion, channelText),
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

    m_progressBar = new QProgressBar(shell);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    shellLayout->addWidget(m_progressBar);

    m_statusLabel = new QLabel(QStringLiteral("ready to download the update package"), shell);
    m_statusLabel->setObjectName(QStringLiteral("status"));
    m_statusLabel->setWordWrap(true);
    shellLayout->addWidget(m_statusLabel);

    auto* actionRow = new QHBoxLayout();
    actionRow->setSpacing(10);

    m_updateButton = new QPushButton((m_target == UpdateTarget::Installer)
            ? QStringLiteral("Update Now")
            : QStringLiteral("Update Now"), shell);
    m_updateButton->setObjectName(QStringLiteral("primary"));
    connect(m_updateButton, &QPushButton::clicked, this, &UpdateDialog::startUpdateFlow);

    m_releaseNotesButton = new QPushButton(QStringLiteral("View Release Page"), shell);
    m_releaseNotesButton->setObjectName(QStringLiteral("subtle"));
    connect(m_releaseNotesButton, &QPushButton::clicked, this, &UpdateDialog::openReleasePage);

    m_laterButton = new QPushButton(QStringLiteral("Remind Later"), shell);
    m_laterButton->setObjectName(QStringLiteral("subtle"));
    connect(m_laterButton, &QPushButton::clicked, this, &UpdateDialog::remindLater);

    m_cancelButton = new QPushButton(QStringLiteral("Cancel Download"), shell);
    m_cancelButton->setObjectName(QStringLiteral("subtle"));
    connect(m_cancelButton, &QPushButton::clicked, this, &UpdateDialog::cancelDownload);

    actionRow->addWidget(m_updateButton);
    actionRow->addWidget(m_releaseNotesButton);
    actionRow->addWidget(m_laterButton);
    actionRow->addWidget(m_cancelButton);
    shellLayout->addLayout(actionRow);

    rootLayout->addWidget(shell);
    updateButtons();
}

// the dialog keeps its own stylesheet so update prompts stay stable even if the main window theme changes later.
void UpdateDialog::applyTheme()
// keeps the apply theme step local to this update dialog flow file so callers can stay focused on intent.
{
    // a local stylesheet keeps the dialog stable even when the global app theme toggles later.
    setStyleSheet(BuildDialogStyle(m_darkTheme));
}

// buttons are refreshed from state in one place to avoid half-updated download controls.
void UpdateDialog::updateButtons()
// handles the update buttons ui work here so widget state changes do not leak across the file.
{
    const bool hasDownload = selectTargetAsset().downloadUrl.isValid();
    const bool downloading = m_downloadReply != nullptr;

    m_updateButton->setEnabled(hasDownload && !downloading);
    m_releaseNotesButton->setEnabled(m_result.release.htmlUrl.isValid() && !downloading);
    m_laterButton->setEnabled(!downloading);
    m_cancelButton->setVisible(downloading);
    m_cancelButton->setEnabled(downloading);
}

void UpdateDialog::setStatusText(const QString& text)
// keeps the set status text step local to this update dialog flow file so callers can stay focused on intent.
{
    if (m_statusLabel)
        m_statusLabel->setText(text);
}

// asset selection prefers the build style the user is already running so updates feel seamless.
ReleaseAssetInfo UpdateDialog::selectTargetAsset() const
// keeps the select target asset step local to this update dialog flow file so callers can stay focused on intent.
{
    if (m_target == UpdateTarget::Installer)
    {
        for (const ReleaseAssetInfo& asset : m_result.release.assets)
        {
            if (asset.name.compare(QStringLiteral("BinaryLens-Setup.exe"), Qt::CaseInsensitive) == 0)
                return asset;
        }
    }
    else
    {
        for (const ReleaseAssetInfo& asset : m_result.release.assets)
        {
            const QString lowerName = asset.name.toLower();
            if (lowerName.startsWith(QStringLiteral("binarylens-portable-")) && lowerName.endsWith(QStringLiteral(".zip")))
                return asset;
        }
    }

    return {};
}

bool UpdateDialog::isInstalledBuild() const
// answers this is installed build check in one place so the surrounding logic stays readable.
{
    const QString appDir = QCoreApplication::applicationDirPath();
    const QString normalized = QDir::toNativeSeparators(appDir).toLower();
    if (normalized.startsWith(QDir::toNativeSeparators(QStandardPaths::writableLocation(QStandardPaths::ApplicationsLocation)).toLower()))
        return true;

    if (normalized.startsWith(QStringLiteral("c:\\program files")) || normalized.startsWith(QStringLiteral("c:\\program files (x86)")))
        return true;

    return QFileInfo::exists(QDir(appDir).filePath(QStringLiteral("unins000.exe")));
}

QString UpdateDialog::summarizePublishedDate() const
// keeps the summarize published date step local to this update dialog flow file so callers can stay focused on intent.
{
    if (!m_result.release.publishedAt.isValid())
        return QStringLiteral("release date unavailable");
    return QStringLiteral("published %1").arg(m_result.release.publishedAt.toLocalTime().toString(QStringLiteral("dd MMM yyyy")));
}

QString UpdateDialog::tempDownloadPathForAsset(const ReleaseAssetInfo& asset) const
// keeps the temp download path for asset step local to this update dialog flow file so callers can stay focused on intent.
{
    const QString tempRoot = QDir(QStandardPaths::writableLocation(QStandardPaths::TempLocation))
        .filePath(QStringLiteral("BinaryLens/updates/%1").arg(m_result.release.version));
    QDir().mkpath(tempRoot);
    return QDir(tempRoot).filePath(asset.name);
}

// once a download begins, the dialog owns the temp file, reply wiring, and visible transfer state.
bool UpdateDialog::beginDownload(const ReleaseAssetInfo& asset)
// keeps the begin download step local to this update dialog flow file so callers can stay focused on intent.
{
    if (m_downloadReply)
        return false;

    if (!IsTrustedGitHubUrl(asset.downloadUrl))
    {
        QMessageBox::warning(this,
            QStringLiteral("Update failed"),
            QStringLiteral("The release asset points to an untrusted host."));
        return false;
    }

    const QString packagePath = tempDownloadPathForAsset(asset);
    delete m_downloadFile;
    m_downloadFile = new QFile(packagePath, this);
    if (!m_downloadFile->open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(this,
            QStringLiteral("Update failed"),
            QStringLiteral("The update package could not be created in the temp directory."));
        delete m_downloadFile;
        m_downloadFile = nullptr;
        return false;
    }

    QNetworkRequest request(asset.downloadUrl);
    request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("BinaryLens/%1").arg(m_result.release.currentVersion));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setTransferTimeout(60000);

    m_activeAsset = asset;
    m_updateStarted = true;
    m_progressBar->setValue(0);
    setStatusText(QStringLiteral("starting download for %1").arg(asset.name));
    m_downloadReply = m_downloadManager->get(request);
    // keeps the connect step local to this update dialog flow file so callers can stay focused on intent.
    connect(m_downloadReply, &QNetworkReply::readyRead, this, [this]() {
        if (m_downloadReply && m_downloadFile)
            m_downloadFile->write(m_downloadReply->readAll());
    });
    connect(m_downloadReply, &QNetworkReply::downloadProgress, this, &UpdateDialog::onDownloadProgress);
    connect(m_downloadReply, &QNetworkReply::finished, this, &UpdateDialog::onDownloadFinished);
    updateButtons();
    return true;
}

// the updater process is launched only after the package is local and the current app can exit cleanly.
bool UpdateDialog::launchUpdater(const ReleaseAssetInfo&, const QString& packagePath)
// keeps the launch updater step local to this update dialog flow file so callers can stay focused on intent.
{
    const QString appDir = QCoreApplication::applicationDirPath();
    const QString helperPath = QDir(appDir).filePath(QStringLiteral("BinaryLensUpdater.exe"));
    const QString appExePath = QDir(appDir).filePath(QStringLiteral("BinaryLensQt.exe"));

    if (!QFileInfo::exists(helperPath))
    {
        QMessageBox::warning(this,
            QStringLiteral("Update failed"),
            QStringLiteral("BinaryLensUpdater.exe was not found next to the app executable."));
        return false;
    }

    const QString mode = (m_target == UpdateTarget::Installer) ? QStringLiteral("installer") : QStringLiteral("portable");
    QStringList arguments;
    arguments
        << QStringLiteral("--mode") << mode
        << QStringLiteral("--package") << packagePath
        << QStringLiteral("--app-dir") << appDir
        << QStringLiteral("--restart-exe") << appExePath;

    const bool started = QProcess::startDetached(helperPath, arguments, appDir);
    if (!started)
    {
        QMessageBox::warning(this,
            QStringLiteral("Update failed"),
            QStringLiteral("The updater helper could not be started."));
        return false;
    }

    setStatusText(QStringLiteral("update package downloaded, restarting to apply update..."));
    return true;
}
