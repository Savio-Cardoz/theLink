#pragma once

#include <functional>
#include <string>

#include "app_common.hpp"

// Shared download pipeline: a command queue consumed by a dedicated
// orchestrator task that streams HTTP content to the SD card via
// AsyncDownloader. Subsystems register a completion handler per target and
// enqueue work with their own URL/filename.

namespace download {

using DoneCallback = std::function<void(bool success, const std::string &filepath)>;

// Create the command queue and spawn the orchestrator task (once).
void start(void);

// Queue a download request. Returns false if the queue was full.
bool enqueue(const char *url, const char *filename, app::DownloadTarget target);

// Register the completion callback for a target (called on success only).
void set_target_handler(app::DownloadTarget target, DoneCallback cb);

// Shared heap diagnostics helper.
void log_heap_info(const char *context);

} // namespace download