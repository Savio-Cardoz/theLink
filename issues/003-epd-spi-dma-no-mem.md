# 003 - QR code not displayed in provisioning mode (E-Paper SPI write fails)

| Field | Value |
|---|---|
| Status | **Fixed** - confirmed on device (QR displays and scans) |
| Found | 2026-10-03 |
| Evidence | `/home/savio/run_1.log` |
| Device log version | `0.4.1`, ESP-IDF v5.4.1, esp32s3 |
| Branch | `fixstuff` |
| Related | [`001-epd-154-heap-exhaustion.md`](./001-epd-154-heap-exhaustion.md) |

## Symptom

In provisioning mode the screen never shows the QR code. The provisioning
service itself starts correctly and the QR payload is generated and pushed to
LVGL, but the panel is never updated.

From `run_1.log`:

```
I (2270) app: Provisioning started
I (2280) QRCODE: Encoding below text with ECC LVL 0 & QR Code Version 10
I (2390) QR_UI: qr_pixel_buffer=0x3c3e1e24, scale=5, offset=(7,7)
I (4200) QR_UI: ui_lock returned 1
I (4200) QR_UI: Successfully pushed binary QR image payload onto layout engine matrix.
I (4470) FLUSH: Executing Global Full Refresh -> Black: 17900, White: 22100
E (4470) driver: writeBytes(5000 bytes) failed: ESP_ERR_NO_MEM
I (4470) driver: [HEAP] writeBytes failure: total_free=8120116, total_min=8113516
                | INTERNAL free=18003, largest_blk=7168 | DMA free=10499 | SPIRAM free=8102328
```

## Root cause

`EPD_Display()` calls `writeBytes(buffer, 5000)` to push the packed 1-bit frame
to the controller. That transfer fails with `ESP_ERR_NO_MEM`, so **no pixels
reach the glass**. Two defects combined to make it invisible.

### 1. The panel buffer was allocated in PSRAM, forcing a per-transfer allocation

`epd_static_buffer` was allocated with `MALLOC_CAP_SPIRAM`. On the ESP32-S3,
`esp_ptr_dma_capable()` is a range check against **internal** SRAM only:

```c
// components/esp_hw_support/include/esp_memory_utils.h:212
inline static bool esp_ptr_dma_capable(const void *p)
{ return (intptr_t)p >= SOC_DMA_LOW && (intptr_t)p < SOC_DMA_HIGH; }

// components/soc/esp32s3/include/soc/soc.h:205
#define SOC_DMA_LOW  0x3FC88000
#define SOC_DMA_HIGH 0x3FD00000
```

That window does not contain PSRAM. The SPI master therefore treats a PSRAM
source as non-DMA-capable and allocates a fresh internal bounce buffer on
**every** transfer:

```c
// components/esp_driver_spi/src/gpspi/spi_master.c:1152
if ((!esp_ptr_dma_capable(send_ptr) || tx_unaligned)) {
    tx_byte_len = (tx_byte_len + alignment - 1) & (~(alignment - 1));
    uint32_t *temp = heap_caps_aligned_alloc(alignment, tx_byte_len, MALLOC_CAP_DMA);
    if (temp == NULL) {
        goto clean_up;      // -> ESP_ERR_NO_MEM
    }
    memcpy(temp, send_ptr, (trans_desc->length + 7) / 8);
    send_ptr = temp;
}
```

`SOC_PSRAM_DMA_CAPABLE` *is* 1 on the S3, but this code path does not use the
external-DMA-aware helper (`esp_dma_is_buffer_aligned(..., AUTO)` /
`esp_ptr_dma_ext_capable()`), so it never benefits from it. In IDF 5.4.1 a
PSRAM SPI source always bounces.

The 5,000-byte bounce allocation is what fails. Note the heap figures: the
`largest_blk=7168` reading is for `MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT`, which
is a *different pool* from `MALLOC_CAP_DMA` (`free=10499`). The DMA pool is
fragmented well below a contiguous 5,000 bytes by this point in boot.

### 2. The failure was silent

`writeBytes()` only logged and returned. `example_lvgl_flush_cb()`
(`main/ui_port.cpp:156`) then called `lv_disp_flush_ready()` unconditionally, so
LVGL believed the flush succeeded. No retry, no error propagation, and the
panel was left showing the previous frame. This is why the failure presented as
"QR not displayed" with no visible error path.

### Why this window is so tight

The heap collapses between `provisioning_start()` and the QR flush. From the log:

| Point in boot | INTERNAL free | largest block |
|---|---|---|
| after `user_app_init` | 205,287 | 110,592 |
| after `display_ctrl::start` | 137,323 | 43,008 |
| after `provisioning_start` | 131,491 | 36,864 |
| at the failed QR flush | **18,003** | **7,168** |

Roughly 113 KB of internal RAM is consumed in that window by BLE, the I2S/codec
buffers, the PCF85063 RTC and Wi-Fi. Wi-Fi alone is configured for
`dynamic rx buffer num: 32` at ~1,600 bytes each, on the order of 51 KB of
internal DMA memory.

The reordering from issue 001 (display before provisioning) helps the *first*
refresh at 2420 ms, which succeeds with room to spare. The QR refresh lands
2 seconds later, in the worst window.

## Fix

### Panel buffer must be DMA-capable internal RAM

```c
// components/user_app/user_app.cpp
- epd_static_buffer = (uint8_t *)heap_caps_malloc(5000, MALLOC_CAP_SPIRAM);
+ epd_static_buffer = (uint8_t *)heap_caps_malloc(5000, MALLOC_CAP_DMA);
```

With the buffer inside `SOC_DMA_LOW..SOC_DMA_HIGH`, `esp_ptr_dma_capable()`
returns true. The alignment condition is also satisfied -
`internal_mem_align_size` is 4 (`spi_common.c:846`), `heap_caps_malloc` returns
4-byte-aligned pointers and `5000 % 4 == 0` - so `tx_unaligned` is false and
**no bounce buffer is allocated at all**. The transfer becomes allocation-free
for the lifetime of the driver.

This is allocated once at `user_app_init()`, when internal free is still
205,287 bytes, so the 5,000 bytes are obtained from a healthy heap rather than
competing at flush time.

Note this partially reverses fix 3 of issue 001. That fix correctly moved the
allocation out of the driver constructor and made ownership explicit, but it
kept `MALLOC_CAP_SPIRAM`, which is the wrong capability for an SPI DMA source.
The external-buffer constructor overload is what made the capability flag
correctable in one place.

### Transfer failures are no longer silent

Added a private helper that retries once and reports honestly:

```c
// components/epaper_driver_bsp/epaper_driver_bsp.cpp
esp_err_t epaper_driver_display::spi_transmit_with_retry(spi_transaction_t *t, const char *what) {
    esp_err_t ret = spi_device_polling_transmit(spi, t);
    if (ret == ESP_OK) return ret;
    ESP_LOGW(TAG, "%s failed: %s - retrying once", what, esp_err_to_name(ret));
    vTaskDelay(pdMS_TO_TICKS(50));
    ret = spi_device_polling_transmit(spi, t);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "%s failed again after retry: %s - panel will show a stale frame", ...);
        EPD_LogHeap(what);
    }
    return ret;
}
```

`SPI_SendByte()` and both `writeBytes()` overloads now route through it, and the
log message names the transfer and states that the frame is stale, so a future
failure is diagnosable instead of looking like a successful flush.

## Verification

- Builds clean; `theLink_esp32s3.bin` at 3,960,528 bytes, 52% of the app
  partition free.
- The bounce-allocation path is provably not taken (source-level: the buffer is
  inside the DMA window and 4-byte aligned).
- **On-device confirmed.** The user flashed the fixed firmware and reported
  that the QR code renders and the provisioning app scans it. The
  `writeBytes(...) failed: ESP_ERR_NO_MEM` line is gone.

## Follow-ups not done here

1. **Internal heap headroom is still thin.** 18,003 bytes free at the QR flush
   is enough now that the SPI path allocates nothing, but very little slack for
   anything else. Consider
   `CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=16` (from 32) in `sdkconfig.defaults`,
   worth roughly 25 KB of internal DMA. Left unchanged here because it trades
   Wi-Fi RX throughput and should be an explicit decision.
   **Done** in [`005-mqtt-task-start-heap.md`](./005-mqtt-task-start-heap.md),
   where the thin internal heap turned out to be what stopped `mqtt_task` from
   being created after provisioning.
2. **`lv_disp_flush_ready()` is still called unconditionally** at
   `main/ui_port.cpp:156`, regardless of whether the panel write succeeded. The
   retry helper now makes the failure loud, but the flush callback still does
   not propagate it. Worth wiring up so LVGL state and panel state cannot
   diverge silently.
3. **The QR refresh is a full-screen refresh.** The 200x200 full blink cycle
   takes 100-500 ms. A partial refresh would be faster and would leave more
   headroom, but only if the QR widget bounds are used to size the update area.