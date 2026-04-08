#include <QApplication>
#include <QByteArray>
#include <QIcon>
#include <QString>

#include "app_version.h"
#include "main_window.h"
#include "services/api_client.h"

namespace
{
// keep noisy platform warnings out of end-user logs when they do not affect app behavior.
void BinaryLensQtMessageHandler(QtMsgType type, const QMessageLogContext& context, const QString& message)
// keeps the binary lens qt message handler step local to this startup flow file so callers can stay focused on intent.
{
    Q_UNUSED(context);

    if (type == QtWarningMsg &&
        (message.contains(QStringLiteral("qt.qpa.screen"), Qt::CaseInsensitive) ||
         message.contains(QStringLiteral("Unable to open monitor interface"), Qt::CaseInsensitive)))
    {
        return;
    }
}
}

// qt startup stays intentionally short so all heavier setup happens after the application object exists.
int main(int argc, char* argv[])
// wires the startup path together and hands control to the normal application flow.
{
    // trim noisy qt diagnostics so normal startup stays clean for end users.
    // qt warnings that matter still flow through; only known noisy startup chatter is suppressed.
    qInstallMessageHandler(BinaryLensQtMessageHandler);
    qputenv("QT_LOGGING_RULES", QByteArrayLiteral("qt.qpa.screen=false"));

    // set application identity before qsettings-backed features such as update reminders are used.
    // once the application object exists, qsettings-backed update and config features can behave normally.
    QApplication app(argc, argv);
    // application identity is set explicitly so settings and updater state live under stable keys.
    app.setOrganizationName(QStringLiteral("BinaryLens"));
    app.setOrganizationDomain(QStringLiteral("binarylens.pages.dev"));
    app.setApplicationName(QStringLiteral("BinaryLens"));
    app.setApplicationVersion(QString::fromUtf8(bl::app::kVersion));
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/binarylens_app.ico")));

    // bootstrap the per-user config before any vt-backed workflow or update prompt is shown.
    EnsureRuntimeConfigReady();

    // once runtime config is ready, the shell can come up with the same assumptions every launch.
    // the main window owns the rest of the interactive startup path from here on.
    MainWindow window;
    window.show();
    // control stays inside the main event loop after this point.
    return app.exec();
}
