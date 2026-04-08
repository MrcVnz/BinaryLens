#include "analysis_worker.h"

#include <exception>
#include <utility>

#include "core/analysis_control.h"

// the worker stays small on purpose: it converts pipeline callbacks into ui-safe signals and nothing more.
AnalysisWorker::AnalysisWorker(QObject* parent)
    : QObject(parent)
// runs the analysis worker pass and returns a focused result for the broader worker handoff pipeline.
{
}

// the worker emits only ui-ready text and never touches widgets directly.
// worker lives off the ui thread so long scans can stream progress safely.
// the worker owns the off-thread execution boundary for both file and url analysis.
void AnalysisWorker::runAnalysis(const QString& target, bool isUrl, bool analystView)
// runs the run analysis pass and returns a focused result for the broader worker handoff pipeline.
{
    // everything inside this block runs away from the widget tree and reports back through signals only.
    try
    {
        ResetAnalysisCancellation();

        // progress is flattened to text here so the ui thread never has to understand engine internals.
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

        // cancellation is checked once more after the run so completion does not race a late stop request.
        if (IsAnalysisCancellationRequested())
        {
            emit cancelled();
            return;
        }

        // all report variants are materialized here once so the ui can switch views without recomputing anything.
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

// cancellation is cooperative and simply forwards the shared stop request into the core pipeline.
void AnalysisWorker::cancel()
// keeps the cancel step local to this worker handoff file so callers can stay focused on intent.
{
    RequestAnalysisCancellation();
}
