#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "esp_heap_caps.h"

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
//
// Logs the internal pool alongside the two capability-restricted pools that
// actually fail during BLE provisioning: MALLOC_CAP_DMA (AES DMA descriptors)
// and the exact BLE controller mask (MALLOC_CAP_8BIT|MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL).
// None of the three can be satisfied from SPIRAM, so internal headroom is the
// real constraint even when PSRAM is nearly empty.
//
// Must stay in sync with BLE_CONTROLLER_MALLOC_CAPS in
// components/bt/controller/esp32/bt.c of the IDF in use.
constexpr uint32_t BLE_CONTROLLER_MALLOC_CAPS = MALLOC_CAP_8BIT | MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL;

void log_heap_info(const char *context);

} // namespace download