#pragma once

// global cancellation switches consumed by long-running analysis stages.
#include <atomic>

void ResetAnalysisCancellation();
void RequestAnalysisCancellation();
bool IsAnalysisCancellationRequested();
