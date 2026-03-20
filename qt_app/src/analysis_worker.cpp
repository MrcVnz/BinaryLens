#include "analysis_worker.h"

#include <exception>
#include <utility>

#include "core/analysis_control.h"

AnalysisWorker::AnalysisWorker(QObject* parent)
    : QObject(parent)
{
}

// the worker emits only ui-ready text and never touches widgets directly.
// worker lives off the ui thread so long scans can stream progress safely.
void AnalysisWorker::runAnalysis(const QString& target, bool isUrl, bool analystView)
{
    try
    {
        ResetAnalysisCancellation();

        auto callback = [this](const AnalysisProgress& progress)
        {
            QString status = QString::fromStdString(progress.stage);
            if (!progress.detail.empty())
            {
                if (!status.isEmpty())
                    status += " — ";
                status += QString::fromStdString(progress.detail);
            }
            emit progressChanged(progress.percent, status);
        };

        // url mode skips progress callbacks because that path is mostly synchronous.
        AnalysisReportData report = isUrl
            ? RunUrlAnalysisDetailed(target.toStdString())
            : RunFileAnalysisDetailed(target.toStdString(), callback);

        if (IsAnalysisCancellationRequested())
        {
            emit cancelled();
            return;
        }

        const QString standard = QString::fromStdString(report.textReport);
        const QString analyst = QString::fromStdString(report.analystTextReport);
        const QString visible = analystView && !analyst.isEmpty() ? analyst : standard;

        emit analysisCompleted(
            visible,
            standard,
            analyst,
            QString::fromStdString(report.iocTextReport),
            QString::fromStdString(report.jsonReport));
    }
    catch (const std::exception& ex)
    {
        emit analysisFailed(QString::fromUtf8(ex.what()));
    }
    catch (...)
    {
        emit analysisFailed(QStringLiteral("BinaryLens hit an unexpected analysis error."));
    }
}

void AnalysisWorker::cancel()
{
    RequestAnalysisCancellation();
}
