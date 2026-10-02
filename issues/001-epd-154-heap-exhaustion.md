# 001 - Heap/DMA exhaustion on 1.54" Waveshare E-Paper after re-provisioning

| Field | Value |
|---|---|
| Status | **Resolved** (verified working on device) |
| Reported | 2026-10-02 |
| Branch | `fixstuff` |
| Baseline commit | `01c0f9a` ("untested" - adds heap instrumentation) |
| Known-good | `5fdabd4` ("Time keeping using NTP", on `origin/master`) |
| Firmware version | `0.4.0` (`version.txt`) |

## Symptom

Pressing the re-provision button put the ESP32 into a crash loop. The logged
cause was a DMA/heap allocation failure raised while loading `dog.bin` from the
SD card.

Two details made this confusing to diagnose:

- The device booted fine on `5fdabd4` and loaded binary images without issue.
- The fault only appeared **after** the provisioning state had been reset once
  via the button. After that point, reflashing the ESP32 did **not** clear it.

## Environment

- Target: `esp32s3`, 8 MB flash, octal PSRAM @ 80 MHz (`CONFIG_SPIRAM_MODE_OCT=y`)
- ESP-IDF: v5.4.1
- Partition table: `partitions_dev.csv` (dev profile, no OTA)
- Display: Waveshare 1.54" 200x200, SPI2 host, `SPI_DMA_CH_AUTO`
- Provisioning: Wi-Fi + BLE, SoftAP/BLE transport, security version 1
- SD card: FAT, 1-bit SDMMC, `CONFIG_FATFS_LFN_HEAP=y`

## Reproduction

1. Flash `01c0f9a` onto a device that is already provisioned and has a valid
   `config.json` on the SD card pointing at an image (`dog.bin`).
2. Hold the reset/provision button (GPIO3, active-low) at power-up.
3. `check_reset_button_at_boot()` (`main/app_main.cpp:41`) fires and the
   firmware erases the NVS partition.
4. The device reboots into provisioning, and the crash loop follows.

## Investigation

Commit `01c0f9a` was the attempt to identify the reason. It added heap
instrumentation rather than a fix:

- `epaper_driver_bsp::EPD_LogHeap()` (`components/epaper_driver_bsp/epaper_driver_bsp.cpp:14`)
  dumps total free/min free internal heap, largest internal block, DMA-capable
  free, and PSRAM free.
- Call sites were added along the boot path in `main/app_main.cpp`
  (`:84`, `:119`, `:124`, `:176`, `:181`) and once in
  `components/user_app/user_app.cpp:50`.
- `main/provisioning.cpp` gained logging in the QR display callback
  (buffer pointer, scale, offset, `ui_lock()` result).
- The E-Paper SPI helpers stopped using `assert(ret == ESP_OK)` and now log the
  failure plus a heap snapshot instead (`epaper_driver_bsp.cpp:164`, `:195`, `:213`).

The instrumentation is still in the tree and is what the diagnosis below is
based on. The two `EPD_LogHeap()` calls that sat on the LVGL flush path
(`main/ui_port.cpp`) were removed once the diagnosis was complete - see
[fix 5](#5-flush-path-heap-logging-removed).

## Root cause

Heap exhaustion at the point where the boot-time allocations, the image decode,
and the Wi-Fi/BLE provisioning stack all peak together. The contributors:

1. **Concurrent large allocations.** The boot path holds, or briefly holds,
   several large buffers at once: the LVGL draw buffer `BUFF_SIZE`
   (200x200x2 = 80,000 bytes, `main/ui_port.cpp:33`), the decoded image canvas
   (80,000 bytes, `main/display_ctrl.cpp:46`), and the per-image decode
   scratchpad (40,000 bytes, `main/display_ctrl.cpp:94`). SPI/E-Paper also
   needs DMA-capable contiguous memory for `spi_device_polling_transmit()`,
   and the SPI bus is configured with `max_transfer_sz = Width * Height`
   (`epaper_driver_bsp.cpp:133`) on `SPI_DMA_CH_AUTO`
   (`epaper_driver_bsp.cpp:141`).
2. **Initialization ordering.** `provisioning_start()` ran *before* the
   display/LVGL tasks were started, and `display_ctrl::boot_kick_if_active()`
   ran *last*, after provisioning had already been kicked off. So a saved image
   referenced by `config.json` was decoded only once the Wi-Fi/BLE stack had
   already claimed its peak allocation.
3. **Allocation inside the driver constructor.** `epaper_driver_display`'s
   constructor called `heap_caps_malloc()` itself
   (`epaper_driver_bsp.cpp:80`), so the buffer's ownership and lifetime were
   implicit and allocated during boot heap churn.
4. **BLE/Wi-Fi footprint.** GATTC (GATT client) was enabled even though this
   firmware only ever acts as a GATT server during provisioning, and Wi-Fi TX
   buffers were at the default 32.
5. **Fragmentation from runtime `malloc` at peak usage.** Repeated
   allocate/free of the 40 KB decode scratchpad during the window where the
   network stack is growing fragments the internal heap and reduces the largest
   contiguous block available to DMA.

## Fixes applied

### 1. `sdkconfig.defaults` - memory footprint

| Setting | Before | After |
|---|---|---|
| `CONFIG_BT_GATTC_ENABLE` | `y` | `n` |
| `CONFIG_BT_BLE_DYNAMIC_ENV_MEMORY` | unset | `y` |
| `CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM` | 32 | 16 |
| `CONFIG_FREERTOS_USE_TRACE_FACILITY` | unset | `y` |
| `CONFIG_FREERTOS_VTASKLIST_INCLUDE_COREID` | unset | `y` |

GATTC is unused by this codebase (no `gattc` symbol appears anywhere under
`main/` or `components/`), so disabling it is free. The FreeRTOS trace options
are diagnostics for future heap/stack work.

> **Correction note.** `CONFIG_LWIP_TCP_RECVMBOX_SIZE=6`,
> `CONFIG_ESP_WIFI_RX_BA_WIN=6` and `CONFIG_ESP_WIFI_RX_MGMT_BUF_NUM_DEF=5` are
> also present in the file, but those values already matched the ESP-IDF 5.4.1
> defaults. They are **no-ops** and contributed nothing to this fix. The only
> Wi-Fi line that is a real delta is `CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM`
> (32 -> 16). The no-op lines can be pruned or annotated at convenience.

### 2. `main/app_main.cpp` - initialization order

Moved the display stack ahead of provisioning so that any image referenced by
`config.json` is decoded before the Wi-Fi/BLE stack reaches peak usage:

- `xTaskCreatePinnedToCore(example_lvgl_port_task, "LVGL", ...)`
- `led_ctrl::start()`
- `display_ctrl::start()`
- `xTaskCreate(ui_overlay_task, "ui_overlay", ...)`
- `display_ctrl::boot_kick_if_active()`

all now execute **before** `provisioning_start()`. Previously the boot kick was
the very last statement in `app_main`.

The constraint that `user_ui_init()` must precede the provisioning task is
preserved - it still runs under `ui_lock()` earlier in `app_main`, since it
calls `lv_obj_clean()` and would otherwise delete the QR widget.

### 3. E-Paper buffer ownership - `epaper_driver_bsp` + `user_app`

Added a constructor overload that accepts a caller-owned buffer:

```cpp
epaper_driver_display(int width, int height, custom_lcd_spi_t _lcd_spi_data,
                       uint8_t *external_buffer);
```

`user_app_init()` now allocates once and passes the pointer in
(`components/user_app/user_app.cpp:40`), instead of the driver allocating
internally.

> **Correction note.** This is *not* static allocation. The buffer is still
> `heap_caps_malloc(5000, MALLOC_CAP_SPIRAM)`, and it still lands in PSRAM -
> which is what the SPI DMA path needs. What actually changed is that the
> allocation moved from the driver constructor to a single explicit site in
> `user_app_init()`, so ownership and lifetime are visible. The original
> 3-argument constructor is retained and still allocates internally.

### 4. `main/display_ctrl.cpp` - error-path cleanup

On the decode-scratchpad allocation failure path, the `FILE *` is now closed
inside the failure branch (`main/display_ctrl.cpp:151`), and the log names the
size and region ("40KB in SPIRAM") so an OOM is distinguishable from other
failures at a glance.

### 5. Flush-path heap logging removed

`example_lvgl_flush_cb()` (`main/ui_port.cpp:93`) called `EPD_LogHeap()` on
**every** flush - once in the full-refresh branch before `EPD_Init()`, once in
the partial-refresh branch before `EPD_Init_Partial()`. Each call performed
four `heap_caps_get_free_size()`/`get_largest_free_block()` queries plus an
`ESP_LOGI`, on a path that runs for every LVGL redraw.

That instrumentation was added to diagnose this issue and is no longer needed,
so both calls were deleted. The refresh/partial-refresh logic itself is
unchanged.

`EPD_LogHeap()` itself is retained, still declared in
`components/epaper_driver_bsp/epaper_driver_bsp.h:70` and still used at:

- `components/user_app/user_app.cpp:50` - one-shot at boot, before E-Paper init.
- `components/epaper_driver_bsp/epaper_driver_bsp.cpp:165`, `:196`, `:214` -
  only on SPI transfer failure, where a heap snapshot is worth the cost.

## Verification

- `build-dev/theLink_esp32s3.bin` builds clean (3,948,800 bytes / 53% of the
  app partition free), no new warnings introduced by these changes.
- On-device: the device boots and loads the binary images, including the
  re-provisioned state that previously produced the crash loop.

## Residual risk

Not addressed by this fix; tracked here so they are not lost.

1. **`assert()` on OOM paths.** `main/display_ctrl.cpp:47` and
   `components/user_app/user_app.cpp:41` still abort the device on allocation
   failure rather than degrading (blank canvas / skip update). The
   decode-scratchpad path (`display_ctrl.cpp:94`) already handles `NULL`
   gracefully; the other two do not.
2. **Only one image is decoded at a time by luck, not by design.** The
   `s_state.active` flag plus the notify-count in `display_ctrl` mean a second
   notification arriving during a decode is dropped rather than queued. Fine
   today, fragile if the download path starts issuing overlapping updates.
3. **`main/app_main.cpp` has no trailing newline** (pre-existing, carried over
   from the reorder).
4. **No regression test.** The crash depends on SD-card contents, NVS state,
   and boot timing. There is no automated way to reproduce it, so a regression
   would not be caught by CI.