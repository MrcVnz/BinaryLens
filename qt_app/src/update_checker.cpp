#include "update_checker.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSettings>
#include <QStringList>
#include <QUrl>

#include "app_version.h"

namespace
{
    bool IsTrustedGitHubHost(const QString& host)
    {
        const QString normalized = host.trimmed().toLower();
        return normalized == QStringLiteral("api.github.com") ||
               normalized == QStringLiteral("github.com") ||
               normalized == QStringLiteral("objects.githubusercontent.com") ||
               normalized == QStringLiteral("release-assets.githubusercontent.com") ||
               normalized.endsWith(QStringLiteral(".githubusercontent.com"));
    }

    bool IsTrustedGitHubUrl(const QUrl& url)
    {
        return url.isValid() && url.scheme() == QStringLiteral("https") && IsTrustedGitHubHost(url.host());
    }

    QString MakeLatestReleaseUrl()
    {
        return QStringLiteral("https://api.github.com/repos/%1/%2/releases/latest")
            .arg(QString::fromUtf8(bl::app::kUpdateOwner), QString::fromUtf8(bl::app::kUpdateRepo));
    }

    // normalize tags like v1.1.0-release into a comparable dotted numeric form.
    QString NormalizeVersionText(const QString& versionText)
    {
        QString trimmed = versionText.trimmed();
        while (!trimmed.isEmpty() && !trimmed.front().isDigit())
            trimmed.remove(0, 1);

        QStringList parts;
        QString current;
        for (const QChar ch : trimmed)
        {
            if (ch.isDigit())
            {
                current += ch;
                continue;
            }

            if (!current.isEmpty())
            {
                parts.push_back(current);
                current.clear();
            }

            if (ch != QLatin1Char('.'))
                break;
        }

        if (!current.isEmpty())
            parts.push_back(current);

        while (parts.size() < 3)
            parts.push_back(QStringLiteral("0"));

        return parts.join(QLatin1Char('.'));
    }

    int CompareNormalizedVersions(const QString& leftVersion, const QString& rightVersion)
    {
        const QStringList leftParts = leftVersion.split(QLatin1Char('.'), Qt::KeepEmptyParts);
        const QStringList rightParts = rightVersion.split(QLatin1Char('.'), Qt::KeepEmptyParts);
        const int count = (leftParts.size() > rightParts.size()) ? leftParts.size() : rightParts.size();

        for (int i = 0; i < count; ++i)
        {
            const int left = (i < leftParts.size()) ? leftParts[i].toInt() : 0;
            const int right = (i < rightParts.size()) ? rightParts[i].toInt() : 0;
            if (left < right)
                return -1;
            if (left > right)
                return 1;
        }

        return 0;
    }
}

UpdateChecker::UpdateChecker(QObject* parent)
    : QObject(parent)
    , m_network(new QNetworkAccessManager(this))
{
    // keep every reply on the ui thread so the dialog can react without cross-thread marshaling.
    connect(m_network, &QNetworkAccessManager::finished, this, &UpdateChecker::onReplyFinished);
}

void UpdateChecker::checkForUpdates()
{
    // use the latest-release endpoint so installer and portable assets can be discovered from one request.
    const QUrl endpoint{MakeLatestReleaseUrl()};
    if (!IsTrustedGitHubUrl(endpoint))
    {
        UpdateCheckResult result;
        result.errorMessage = QStringLiteral("Update endpoint is not trusted.");
        emit checkFinished(result);
        return;
    }

    QNetworkRequest request{endpoint};
    request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("BinaryLens/%1").arg(currentVersion()));
    request.setRawHeader("Accept", "application/vnd.github+json");
    request.setRawHeader("X-GitHub-Api-Version", "2022-11-28");
    m_network->get(request);
}

QString UpdateChecker::currentVersion() const
{
    return QString::fromUtf8(bl::app::kVersion);
}

bool UpdateChecker::isVersionSuppressed(const QString& version) const
{
    QSettings settings;
    settings.beginGroup(settingsGroup());
    const QString ignoredVersion = settings.value(QStringLiteral("ignored_version")).toString();
    const QDateTime remindAfter = settings.value(QStringLiteral("remind_after_utc")).toDateTime();
    settings.endGroup();

    if (!ignoredVersion.isEmpty() && normalizeVersion(ignoredVersion) == normalizeVersion(version))
        return true;

    return remindAfter.isValid() && remindAfter > QDateTime::currentDateTimeUtc();
}

void UpdateChecker::suppressVersion(const QString& version)
{
    QSettings settings;
    settings.beginGroup(settingsGroup());
    settings.setValue(QStringLiteral("ignored_version"), version);
    settings.remove(QStringLiteral("remind_after_utc"));
    settings.endGroup();
}

void UpdateChecker::deferReminder(int hours)
{
    QSettings settings;
    settings.beginGroup(settingsGroup());
    settings.remove(QStringLiteral("ignored_version"));
    settings.setValue(QStringLiteral("remind_after_utc"), QDateTime::currentDateTimeUtc().addSecs(hours * 3600));
    settings.endGroup();
}

void UpdateChecker::onReplyFinished(QNetworkReply* reply)
{
    UpdateCheckResult result;
    if (!reply)
    {
        result.errorMessage = QStringLiteral("Update check returned no reply object.");
        emit checkFinished(result);
        return;
    }

    if (reply->error() != QNetworkReply::NoError)
    {
        result.errorMessage = reply->errorString();
        reply->deleteLater();
        emit checkFinished(result);
        return;
    }

    if (!IsTrustedGitHubUrl(reply->url()))
    {
        result.errorMessage = QStringLiteral("Update reply came from an untrusted host.");
        reply->deleteLater();
        emit checkFinished(result);
        return;
    }

    result = buildResultFromPayload(reply->readAll());
    reply->deleteLater();
    emit checkFinished(result);
}

UpdateCheckResult UpdateChecker::buildResultFromPayload(const QByteArray& payload) const
{
    UpdateCheckResult result;
    result.release.currentVersion = currentVersion();

    QJsonParseError parseError = {};
    const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
    {
        result.errorMessage = QStringLiteral("Could not parse GitHub release metadata.");
        return result;
    }

    const QJsonObject root = document.object();
    ReleaseInfo release;
    release.valid = true;
    release.currentVersion = currentVersion();
    release.tagName = root.value(QStringLiteral("tag_name")).toString();
    release.version = normalizeVersion(release.tagName);
    release.releaseName = root.value(QStringLiteral("name")).toString();
    release.body = root.value(QStringLiteral("body")).toString();
    release.htmlUrl = QUrl(root.value(QStringLiteral("html_url")).toString());
    if (!IsTrustedGitHubUrl(release.htmlUrl))
        release.htmlUrl = {};
    release.publishedAt = QDateTime::fromString(root.value(QStringLiteral("published_at")).toString(), Qt::ISODate);
    release.prerelease = root.value(QStringLiteral("prerelease")).toBool(false);
    release.draft = root.value(QStringLiteral("draft")).toBool(false);

    const QJsonArray assets = root.value(QStringLiteral("assets")).toArray();
    for (const QJsonValue& assetValue : assets)
    {
        const QJsonObject assetObject = assetValue.toObject();
        ReleaseAssetInfo asset;
        asset.name = assetObject.value(QStringLiteral("name")).toString();
        asset.downloadUrl = QUrl(assetObject.value(QStringLiteral("browser_download_url")).toString());
        asset.size = static_cast<qint64>(assetObject.value(QStringLiteral("size")).toDouble(-1));
        if (!asset.name.isEmpty() && IsTrustedGitHubUrl(asset.downloadUrl))
            release.assets.push_back(asset);
    }

    result.success = true;
    result.release = release;
    result.updateAvailable = compareVersions(normalizeVersion(currentVersion()), release.version) < 0 && !release.draft;
    result.suppressed = result.updateAvailable && isVersionSuppressed(release.version);
    return result;
}

QString UpdateChecker::normalizeVersion(const QString& versionText)
{
    return NormalizeVersionText(versionText);
}

int UpdateChecker::compareVersions(const QString& leftVersion, const QString& rightVersion)
{
    return CompareNormalizedVersions(leftVersion, rightVersion);
}

QString UpdateChecker::settingsGroup()
{
    return QStringLiteral("updates");
}
