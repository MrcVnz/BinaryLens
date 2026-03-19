#pragma once

#include <QObject>
#include <QString>

#include "core/analysis_engine.h"

// background worker that runs file or url analysis away from the gui thread.
class AnalysisWorker final : public QObject
{
    Q_OBJECT
public:
    explicit AnalysisWorker(QObject* parent = nullptr);

public slots:
    // starts the requested analysis mode and forwards progress back to the ui.
    void runAnalysis(const QString& target, bool isUrl, bool analystView);
    // requests cooperative cancellation for long-running stages.
    void cancel();

signals:
    void progressChanged(int percent, const QString& statusLine);
    void analysisCompleted(const QString& visibleReport,
                           const QString& standardReport,
                           const QString& analystReport,
                           const QString& iocReport,
                           const QString& jsonReport);
    void analysisFailed(const QString& errorText);
    void cancelled();
};
