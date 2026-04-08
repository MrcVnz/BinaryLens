#include "update_checker.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QStringList>
#include <QUrl>

#include "app_version.h"

namespace
{
    // host checks stay strict because update metadata and assets should only come from known github endpoints.
    bool IsTrustedGitHubHost(const QString& host)
    // answers this is trusted git hub host check in one place so the surrounding logic stays readable.
    {
        const QString normalized = host.trimmed().toLower();
        return normalized == QStringLiteral("api.github.com") ||
               normalized == QStringLiteral("github.com") ||
               normalized == QStringLiteral("objects.githubusercontent.com") ||
               normalized == QStringLiteral("release-assets.githubusercontent.com") ||
               normalized.endsWith(QStringLiteral(".githubusercontent.com"));
    }

    // scheme and host are both enforced so redirects cannot silently downgrade transport.
    bool IsTrustedGitHubUrl(const QUrl& url)
    // answers this is trusted git hub url check in one place so the surrounding logic stays readable.
    {
        return url.isValid() && url.scheme() == QStringLiteral("https") && IsTrustedGitHubHost(url.host());
    }

    // keep endpoint construction in one place so repo ownership changes do not scatter through the ui.
    QString MakeLatestReleaseUrl()
    // keeps the make latest release url step local to this update checks file so callers can stay focused on intent.
    {
        return QStringLiteral("https://api.github.com/repos/%1/%2/releases/latest")
            .arg(QString::fromUtf8(bl::app::kUpdateOwner), QString::fromUtf8(bl::app::kUpdateRepo));
    }

    // normalize tags like v1.1.0-release into a comparable dotted numeric form.
    QString NormalizeVersionText(const QString& versionText)
    // keeps the normalize version text step local to this update checks file so callers can stay focused on intent.
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

    // numeric comparison avoids lexical mistakes such as 1.10 being treated as older than 1.9.
    int CompareNormalizedVersions(const QString& leftVersion, const QString& rightVersion)
    // keeps the compare normalized versions step local to this update checks file so callers can stay focused on intent.
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
// handles the update checker ui work here so widget state changes do not leak across the file.
{
    // keep every reply on the ui thread so the updater prompt can react without cross-thread marshaling.
    connect(m_network, &QNetworkAccessManager::finished, this, &UpdateChecker::onReplyFinished);
}

// this only fetches metadata; download choice and install flow stay elsewhere.
void UpdateChecker::checkForUpdates()
// keeps the check for updates step local to this update checks file so callers can stay focused on intent.
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
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    m_network->get(request);
}

QString UpdateChecker::currentVersion() const
// keeps the current version step local to this update checks file so callers can stay focused on intent.
{
    return QString::fromUtf8(bl::app::kVersion);
}

// reply handling stays centralized so trust checks and parse errors are reported the same way every time.
void UpdateChecker::onReplyFinished(QNetworkReply* reply)
// keeps the on reply finished step local to this update checks file so callers can stay focused on intent.
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

// release parsing prefers explicit trust checks over blindly accepting every field github returns.
UpdateCheckResult UpdateChecker::buildResultFromPayload(const QByteArray& payload) const
// builds this update checks fragment in one place so the surrounding code can stay focused on flow.
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

    // only trusted asset urls survive this pass so later download code gets a clean list.
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
    result.suppressed = false;
    return result;
}

QString UpdateChecker::normalizeVersion(const QString& versionText)
// keeps the normalize version step local to this update checks file so callers can stay focused on intent.
{
    return NormalizeVersionText(versionText);
}

int UpdateChecker::compareVersions(const QString& leftVersion, const QString& rightVersion)
// keeps the compare versions step local to this update checks file so callers can stay focused on intent.
{
    return CompareNormalizedVersions(leftVersion, rightVersion);
}
