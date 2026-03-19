#include <QApplication>
#include <QByteArray>
#include <QIcon>
#include <QString>

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
    qInstallMessageHandler(BinaryLensQtMessageHandler);
    qputenv("QT_LOGGING_RULES", QByteArrayLiteral("qt.qpa.screen=false"));

    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/binarylens_app.ico")));
    MainWindow window;
    window.show();
    return app.exec();
}
