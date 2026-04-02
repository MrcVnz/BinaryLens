#include <QApplication>
#include <QByteArray>
#include <QIcon>
#include <QString>

#include "app_version.h"
#include "main_window.h"

namespace
{
void BinaryLensQtMessageHandler(QtMsgType type, const QMessageLogContext& context, const QString& message)
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

int main(int argc, char* argv[])
{
    // trim noisy qt diagnostics so normal startup stays clean for end users.
    qInstallMessageHandler(BinaryLensQtMessageHandler);
    qputenv("QT_LOGGING_RULES", QByteArrayLiteral("qt.qpa.screen=false"));

    // set application identity before qsettings-backed features such as update reminders are used.
    QApplication app(argc, argv);
    app.setOrganizationName(QStringLiteral("BinaryLens"));
    app.setOrganizationDomain(QStringLiteral("binarylens.pages.dev"));
    app.setApplicationName(QStringLiteral("BinaryLens"));
    app.setApplicationVersion(QString::fromUtf8(bl::app::kVersion));
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/binarylens_app.ico")));
    MainWindow window;
    window.show();
    return app.exec();
}
