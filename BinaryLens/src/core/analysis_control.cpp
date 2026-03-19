#include "core/analysis_control.h"
// shared cancellation state backing the analysis stop flow.

namespace {
    std::atomic<bool> g_cancelRequested{false};
}

void ResetAnalysisCancellation()
{
    g_cancelRequested.store(false, std::memory_order_relaxed);
}

void RequestAnalysisCancellation()
{
    g_cancelRequested.store(true, std::memory_order_relaxed);
}

bool IsAnalysisCancellationRequested()
{
    return g_cancelRequested.load(std::memory_order_relaxed);
}
