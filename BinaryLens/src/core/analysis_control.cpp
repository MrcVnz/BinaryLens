#include "core/analysis_control.h"

// shared cancellation state backing the analysis stop flow.
// this file stays intentionally tiny because many hot paths poll it frequently.

namespace {
// a process-wide flag matches the current single-analysis runtime model.
    // one flag is enough here because work only needs a fast cooperative stop signal.
    std::atomic<bool> g_cancelRequested{false};
}

// reset happens right before new work starts so a previous stop request does not leak into the next run.
void ResetAnalysisCancellation()
// runs the reset analysis cancellation pass and returns a focused result for the broader analysis cancellation flow pipeline.
{
    // relaxed ordering is enough because this flag carries no payload beyond yes-or-no cancellation.
    g_cancelRequested.store(false, std::memory_order_relaxed);
}

// cancellation is intentionally write-only here to keep worker code simple and lock-free.
void RequestAnalysisCancellation()
// runs the request analysis cancellation pass and returns a focused result for the broader analysis cancellation flow pipeline.
{
    // the pipeline only needs to observe that cancellation happened, not exactly when it became visible.
    g_cancelRequested.store(true, std::memory_order_relaxed);
}

// readers poll this cheaply from hot loops and worker callbacks.
bool IsAnalysisCancellationRequested()
// answers this is analysis cancellation requested check in one place so the surrounding logic stays readable.
{
    // readers can poll this frequently without paying for heavier synchronization primitives.
    return g_cancelRequested.load(std::memory_order_relaxed);
}
