#pragma once

#include <QDateTime>
#include <QList>
#include <QObject>
#include <QString>
#include <QUrl>

class QNetworkAccessManager;
class QNetworkReply;

struct ReleaseAssetInfo
{
    QString name;
    QUrl downloadUrl;
    qint64 size = -1;
};

struct ReleaseInfo
{
    bool valid = false;
    QString currentVersion;
    QString version;
    QString tagName;
    QString releaseName;
    QString body;
    QUrl htmlUrl;
    QDateTime publishedAt;
    QList<ReleaseAssetInfo> assets;
    bool prerelease = false;
    bool draft = false;
};

struct UpdateCheckResult
{
    bool success = false;
    bool updateAvailable = false;
    bool suppressed = false;
    QString errorMessage;
    ReleaseInfo release;
};

Q_DECLARE_METATYPE(UpdateCheckResult)

// lightweight github releases client that keeps update checks asynchronous and deterministic.
class UpdateChecker final : public QObject
{
    Q_OBJECT
public:
    explicit UpdateChecker(QObject* parent = nullptr);

    void checkForUpdates();
    QString currentVersion() const;

signals:
    void checkFinished(const UpdateCheckResult& result);

private slots:
    void onReplyFinished(QNetworkReply* reply);

private:
    UpdateCheckResult buildResultFromPayload(const QByteArray& payload) const;
    static QString normalizeVersion(const QString& versionText);
    static int compareVersions(const QString& leftVersion, const QString& rightVersion);

    QNetworkAccessManager* m_network = nullptr;
};
