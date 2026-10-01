# Feature — Always-on Wake Word ("Hi,ESP")

Status: **design complete, not implemented**
Target: Waveshare ESP32-S3-ePaper-1.54 (ES8311 codec + one analog mic)
Wake word: bundled ESP-SR WakeNet9 model `wn9_hiesp`, spoken phrase **"Hi,ESP"**

---

## 1. Summary

Add a low-priority FreeRTOS task that keeps the ES8311 microphone open and streams
16 kHz mono PCM into ESP-SR's standalone WakeNet9 engine. On a detection the device
publishes an MQTT event, flashes the LED ring, and plays an acknowledgement sound from
the SD card.

The model ships on the SD card (`CONFIG_MODEL_IN_SDCARD=y`), so there is no flash
partition, no partition-table change, and no OTA interaction with model data.

The single hard problem is that playback and capture share **one** ES8311 codec and
**one** I2S data interface. Every other item in this document is straightforward once
that is solved (see §4.2 and §5.3).

---

## 2. Decision record

| Decision | Choice | Rationale |
| --- | --- | --- |
| Wake word | `wn9_hiesp` = "Hi,ESP" | Bundled with ESP-SR, no training or vendor request needed. |
| Engine | Standalone `esp_wn_iface_t` (no AFE) | No AEC/VAD/NS requested for phase 1; ~13% of one core, 20 KB IRAM, 347 KB PSRAM. |
| Model storage | SD card, `CONFIG_MODEL_IN_SDCARD=y` | User choice. Keeps app flash for OTA. |
| Always-on | Yes, task starts after SD mount | Wake available with no button press. |
| On detection | MQTT event + LED flash + ack sound from SD | User choice (both answers in the questionnaire). |
| Listening during playback | Paused | No AEC; self-triggering is worse than missing a wake word while the device is talking. |
| NS / AEC / VAD | Off for phase 1 | Deliberate. See §8 for the follow-up if false alarms dominate. |
| Sensitivity | Runtime threshold via `wn->set_det_threshold()` | Confirmed available in the standalone interface (`esp_wn_iface.h`). |
| Custom model ("Hi Link") | Deferred | User chose the bundled phrase for now. Requires a separate project; see §10. |

---

## 3. Assumptions

Each item is marked **[V]** verified by reading the repository / ESP-SR source, or
**[A]** assumed and to be confirmed on hardware.

### 3.1 Hardware

* **[V]** Microphone is the ES8311 ADC line, not a raw-ADC input: I2S `mclk=14`, `bclk=15`,
  `din=16`, `ws=38`, `dout=45` (`components/codec_board/board_cfg.txt`,
  `codec_init.c:397-470`), codec type `S3_ePaper_1_54` (`audio_bsp.c:20`).
* **[V]** The mic amplifier enable is `pa_pin = GPIO46`; `esp_codec_dev_open(record, …)`
  drives it high through `es8311_pa_power()`, and `esp_codec_dev_close(playback, …)`
  drives it low.
* **[A]** PA polarity is active-high (matches `es8311_pa_power`). Confirm in P0 by toggling
  GPIO46 and listening for speaker output.
* **[A]** One microphone only. If `wn9_hiesp` reports `get_channel_num() == 3`, mono input is
  duplicated into 3 interleaved channels — see §7 OQ-1.
* **[A]** PSRAM is 8 MB. `sdkconfig.defaults:18-20` only proves octal PSRAM is enabled;
  capacity was never confirmed from the vendor spec. Relevant because the model is loaded
  to PSRAM (`DET_MODE_95*`).
* **[A]** Mic gain of 30 dB (the current default, `codec_init.c:534-536`) is adequate for
  0.5–1 m talk distance. P0 logs RMS dBFS so the gain can be tuned from real data.

### 3.2 ESP-SR / toolchain

* **[V]** Local ESP-IDF is v5.4.1 (`sdkconfig.defaults` header comment says 5.5.1); ESP-SR
  supports IDF ≥ 5.0, so v5.4.1 is fine.
* **[V]** `espressif/esp-sr` is delivered as prebuilt static libraries per target
  (`esp-sr/CMakeLists.txt`), including `libwakenet.a`. No esp-dl kernel source build.
* **[V]** `esp-sr/CMakeLists.txt` only emits the `srmodels_bin` target when a partition named
  `model` exists in the custom partition table. `partitions_dev.csv` has none, so with
  SD-card loading the build prints "Failed to find model in partition table file" and moves on.
  **No partition-table change is required.**
* **[V]** `det_mode_t`: `DET_MODE_90`/`DET_MODE_95` (1 ch, flash/PSRAM) and
  `DET_MODE_2CH_90/95`, `DET_MODE_3CH_90/95` (PSRAM variants). PSRAM modes are mandatory here.
* **[V]** `esp_wn_iface_t` exposes `get_channel_num()`, `get_samp_chunksize()`,
  `get_samp_rate()`, `set_det_threshold(model, thr, word_index)` (range 0.4–0.9999,
  index starts at 1), `get_triggered_channel()`, `clean()`, `destroy()`.
* **[V]** `detect()` returns `wakenet_state_t`: `WAKENET_NO_DETECT`, `WAKENET_CHANNEL_VERIFIED`,
  `WAKENET_DETECTED`. No per-frame score is exposed, so the threshold setter is the only
  runtime sensitivity control.
* **[A]** 32 ms frames at 16 kHz (512 samples) are the right granularity. The code reads
  `get_samp_chunksize()`/`get_samp_rate()` at runtime instead of hardcoding them.
* **[V]** Source of the model files for the export script:
  `managed_components/espressif__esp-sr/model/wakenet_model/wn9_hiesp/`
  (contains `_MODEL_INFO_`, `wn9_data`, `wn9_index`). Re-verify the path after the
  component is fetched — the directory layout has changed between ESP-SR releases.
* **[A]** CPU: 4.3 ms of detection per 32 ms frame (~13% of one core) plus ~0.5 ms of
  I2S/PSRAM overhead. Needs a measurement on real hardware (P2).

### 3.3 Codebase

* **[V]** Boot order (`main/app_main.cpp`): `identity_init()` 68 → ctrl `init()` 72-76 →
  `user_app_init()` 78 → SD mount + `config_store_load()` 104-108 → `audio_ctrl::start()`
  171 → `display_ctrl::boot_kick_if_active()` 176.
* **[V]** `wake_ctrl::init()` belongs with the other `init()` calls (registers
  `cmd/wakeup`); `wake_ctrl::start()` belongs immediately after `audio_ctrl::start()`
  so the SD card is mounted and `config.json` is already parsed.
* **[V]** `audio_bsp_init()` is currently called from the audio task only
  (`audio_ctrl.cpp:39`) and is not idempotent. Two tasks calling it would double-init the
  codec, so the BSP must guard it.
* **[V]** With `reuse_dev = false` (`audio_bsp.c:26`) playback and capture are **two**
  `esp_codec_dev` handles (`codec_init.c:461-469`) wrapping **one** `es8311_codec` object
  and **one** I2S data interface. Closing playback powers the shared codec down while the
  record handle still believes it is open — the mic would then read silence or garbage.
  §5.3 fixes this by switching to `reuse_dev = true` (one handle, one `is_open` flag).
* **[V]** Publish/command conventions: `mqtt_register_cmd(topic, handler)` and
  `app::mqtt_publish(topic, payload, qos, retain)` (`status_ctrl.cpp:80,97`).
* **[V]** Config persistence convention: `config_store_save()` serializes each subsystem
  into `cJSON` and writes `/sdcard/config.json`; `config_store_load()` applies them
  (`config_store.cpp:14-106`).
* **[V]** The LED ring can be driven without touching saved state by calling
  `led_ctrl::handle_rgb_command()` with `"persist": false` (`led_ctrl.cpp:301,419-422`);
  a `duration` turns the ring off again on expiry (`led_ctrl.cpp:370-378,475`).
* **[V]** `i2s_music()`, `i2s_echo()`, `audio_play_init()`, `audio_playback_write()` in
  `audio_bsp.c` are unused dead code that duplicates the lifecycle this feature needs;
  they are removed in §5.3.

### 3.4 Product decisions encoded as defaults

* Ack sound filename defaults to empty (silent) until a sound is placed on the SD card;
  MQTT + LED still fire. Prevents a boot-time error on a fresh card.
* `wake.enabled` defaults to **true**.
* Re-trigger lockout of 1.5 s after a detection, so one utterance cannot fire repeatedly.
* Detection events are **not** persisted and are **not** retained on the MQTT topic
  (QoS 1, retain 0) — same rationale as `evt/status` (`status_ctrl.cpp:76-82`).

---

## 4. Architecture

### 4.1 Runtime flow

```
app_main
 ├─ wake_ctrl::init()                 defaults + cmd/wakeup registration
 ├─ SD mount → config_store_load()    applies wake.enabled / model / mode / threshold
 └─ wake_ctrl::start()                spawns "wake" task, core 0, prio 4, 8192 stack

wake task loop
 ├─ load model once (esp_srmodel_init("/sdcard/srmodel") + filter "hiesp")
 │    on failure: log once, retry every 60 s, never block boot
 ├─ loop:
 │    audio_lock(200 ms)
 │      audio_record_begin(16000, 1)      idempotent; PA forced OFF
 │      audio_record_read(frame)          1 frame = get_samp_chunksize() samples
 │    audio_unlock()
 │    wn->detect(md, frame)               CPU only, no lock held
 │    on WAKENET_DETECTED:
 │        wn->clean(md)                   avoid immediate re-trigger
 │        publish evt/wakeup (QoS 1)
 │        led_ctrl flash via cmd payload (persist:false)
 │        audio_ctrl::play(ack.wav)       audio task blocks on audio_lock
 │        1.5 s cooldown
```

### 4.2 Codec ownership

A single FreeRTOS mutex in `audio_bsp` plus a single `audio_session_t` is the whole
arbitration mechanism:

* the wake task holds the mutex for **one frame** at a time, so playback can interleave
  between frames with ≤32 ms latency;
* the audio task holds it for the whole file, so the mic is closed and PA-off while sound
  plays — this is what makes "no barge-in" free;
* `audio_record_begin()` is idempotent, so per-frame locking does not reopen the codec
  every 32 ms; it only reopens after a playback session closed it;
* `audio_playback_begin()` / `audio_record_begin()` each close whatever session was open
  before opening with their own sample format, so there is never a window where two
  callers believe they own the ES8311.

`reuse_dev = true` (`audio_bsp.c:26`) makes record and playback the *same*
`esp_codec_dev` handle, which removes the possibility of the two handles disagreeing
about the shared codec state — the root cause of the current breakage.

### 4.3 Detection response

| Action | Mechanism | Configurable |
| --- | --- | --- |
| MQTT event | `evt/wakeup`, JSON below, QoS 1, retain 0 | always on |
| LED flash | `led_ctrl::handle_rgb_command()` with `persist:false` | colour/brightness/duration |
| Ack sound | `audio_ctrl::play()` from `/sdcard/<name>` | `wake.ack_sound` |

```json
{"event":"wake","word":"Hi,ESP","model":"wn9_hiesp","channel":0,
 "threshold":0.635,"uptime_ms":84213,"level_dbfs":-28.4}
```

---

## 5. Change set

Files changed: 14 modified, 3 new. Files deliberately **not** touched are listed in §5.14.

### 5.1 `main/idf_component.yml`

```diff
 dependencies:
   ## Required IDF version
   idf:
     version: '>=4.1.0'
   lvgl/lvgl: ^9.3.0
   espressif/network_provisioning: ^1.2.4
   espressif/qrcode: ^0.2.0
   espressif/esp_codec_dev: ~1.3.4
+  espressif/esp-sr: ^2.5.5
```

### 5.2 `sdkconfig.defaults`

```diff
 CONFIG_CODEC_ES8311_SUPPORT=y
+
+# Always-on wake word ("Hi,ESP"): WakeNet9 model lives on the SD card, so no
+# `model` partition is needed and srmodels.bin is never flashed.
+CONFIG_MODEL_IN_SDCARD=y
+CONFIG_SR_WN_WN9_HIESP=y
```

> `CONFIG_SR_WN_WN9_HIESP` is the Kconfig symbol behind the `SR_WN_WN9_HIESP` entry
> ("Hi,ESP (wn9_hiesp)") in `esp-sr`'s `Kconfig`. Confirm the generated `CONFIG_` prefix
> from `build*/config/sdkconfig.h` after the first build. `CONFIG_AFE_INTERFACE_V1` is the
> default of its choice group and needs no entry.

### 5.3 `components/audio_bsp/audio_bsp.h` and `.c`

One handle, one mutex, symmetric begin/end pairs, dead code removed, PA under our control.

```diff
--- a/components/audio_bsp/audio_bsp.h
+++ b/components/audio_bsp/audio_bsp.h
@@
 #ifdef __cplusplus
 extern "C" {
 #endif
 
+#include <stdbool.h>
+#include <stdint.h>
+
 void audio_bsp_init(void);
-void i2s_music(void *args);
-void i2s_echo(void *arg);
 void audio_playback_set_vol(uint8_t vol);
-uint8_t *i2s_get_handle(uint32_t *len);
-
-void audio_play_init(void);
-
-void audio_playback_read(void *data_ptr,uint32_t len);
-
-void audio_playback_write(void *data_ptr,uint32_t len);
+
+bool audio_lock(uint32_t timeout_ms);
+void audio_unlock(void);
+
+bool audio_record_begin(uint32_t sample_rate, uint8_t channel);
+int  audio_record_read(void *data, uint32_t len);
+void audio_record_end(void);
+
+bool audio_playback_begin(uint32_t sample_rate, uint8_t channel);
+int  audio_playback_write(void *data, uint32_t len);
+void audio_playback_end(void);
+
+void audio_pa_set(bool on);
 
 #ifdef __cplusplus
 }
 #endif
```

```diff
--- a/components/audio_bsp/audio_bsp.c
+++ b/components/audio_bsp/audio_bsp.c
@@
 #include "esp_codec_dev.h"
 #include "esp_heap_caps.h"
+#include "driver/gpio.h"
+#include "freertos/semphr.h"
+#include "user_config.h"
 
-
-esp_codec_dev_handle_t playback = NULL;
-esp_codec_dev_handle_t record = NULL;
-
-
-extern const uint8_t music_pcm_start[] asm("_binary_canon_pcm_start");
-extern const uint8_t music_pcm_end[]   asm("_binary_canon_pcm_end");
+static const char *TAG = "audio_bsp";
+
+typedef enum {
+	SESSION_NONE = 0,
+	SESSION_RECORD,
+	SESSION_PLAYBACK,
+} audio_session_t;
+
+static esp_codec_dev_handle_t s_codec = NULL;
+static SemaphoreHandle_t s_codec_lock = NULL;
+static bool s_inited = false;
+static audio_session_t s_session = SESSION_NONE;
@@
 void audio_bsp_init(void)
 {
-  	set_codec_board_type("S3_ePaper_1_54");
+	if (s_inited) {
+		return;
+	}
+	set_codec_board_type("S3_ePaper_1_54");
 	codec_init_cfg_t codec_cfg = 
     {
         .in_mode = CODEC_I2S_MODE_STD,
         .out_mode = CODEC_I2S_MODE_STD,
         .in_use_tdm = false,
-        .reuse_dev = false,
+        .reuse_dev = true,
     };
   	ESP_ERROR_CHECK(init_codec(&codec_cfg));
-  	playback = get_playback_handle();
-  	record = get_record_handle();
+	s_codec = get_playback_handle();
+	s_codec_lock = xSemaphoreCreateMutex();
+	s_inited = true;
+	ESP_LOGI(TAG, "codec ready (single shared handle: %p)", s_codec);
 }
```

The four dead/duplicate helpers (`i2s_music`, `i2s_echo`, `audio_play_init`,
`audio_playback_read`, `audio_playback_write`, `i2s_get_handle`) are deleted; the only
caller of the record path, `audio_playback_read()`, has none today (§3.3).

New implementation body (continues the state block above):

```c
bool audio_lock(uint32_t timeout_ms)
{
	return s_codec_lock != NULL &&
		   xSemaphoreTake(s_codec_lock, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

void audio_unlock(void)
{
	if (s_codec_lock != NULL) {
		xSemaphoreGive(s_codec_lock);
	}
}

void audio_pa_set(bool on)
{
	gpio_set_level(AUDIO_PA_PIN, on ? 1 : 0);
}

static bool open_codec(uint32_t sample_rate, uint8_t channel)
{
	esp_codec_dev_sample_info_t fs = {
		.sample_rate = sample_rate,
		.channel = channel,
		.bits_per_sample = 16,
	};
	if (s_codec == NULL) {
		return false;
	}
	if (esp_codec_dev_open(s_codec, &fs) != ESP_CODEC_DEV_OK) {
		ESP_LOGE(TAG, "esp_codec_dev_open(%u Hz, %u ch) failed", sample_rate, channel);
		return false;
	}
	return true;
}

static void close_codec(void)
{
	if (s_session == SESSION_NONE) {
		return;
	}
	esp_codec_dev_close(s_codec);
	s_session = SESSION_NONE;
	audio_pa_set(false);
}

bool audio_record_begin(uint32_t sample_rate, uint8_t channel)
{
	if (s_session == SESSION_RECORD) {
		return true;
	}
	close_codec();
	if (!open_codec(sample_rate, channel)) {
		return false;
	}
	s_session = SESSION_RECORD;
	esp_codec_dev_set_in_gain(s_codec, 30.0);
	audio_pa_set(false);
	return true;
}

int audio_record_read(void *data, uint32_t len)
{
	if (s_session != SESSION_RECORD) {
		return -1;
	}
	return esp_codec_dev_read(s_codec, data, len) == ESP_CODEC_DEV_OK ? (int)len : -1;
}

void audio_record_end(void)
{
	close_codec();
}

bool audio_playback_begin(uint32_t sample_rate, uint8_t channel)
{
	if (s_session == SESSION_PLAYBACK) {
		return true;
	}
	close_codec();
	if (!open_codec(sample_rate, channel)) {
		return false;
	}
	s_session = SESSION_PLAYBACK;
	audio_pa_set(true);
	return true;
}

int audio_playback_write(void *data, uint32_t len)
{
	if (s_session != SESSION_PLAYBACK) {
		return -1;
	}
	return esp_codec_dev_write(s_codec, data, len) == ESP_CODEC_DEV_OK ? (int)len : -1;
}

void audio_playback_end(void)
{
	close_codec();
}

void audio_playback_set_vol(uint8_t vol)
{
	if (s_codec != NULL) {
		esp_codec_dev_set_out_vol(s_codec, (float)vol);
	}
}
```

> One `s_session` enum instead of two booleans, because the ES8311 and the I2S channel are
> shared: there can only ever be one open session, and **any** close invalidates **any**
> open. `audio_playback_begin()` and `audio_record_begin()` therefore close first and
> reopen with the sample format their caller needs — that transition is what makes the
> mic go quiet and then come back after a sound finishes. This invariant is exactly what
> the old two-handle setup violated (`codec_init.c:461-469` + `audio_ctrl.cpp:86,108`).

### 5.4 `main/user_config.h`

```diff
 #define Audio_PWR_PIN GPIO_NUM_42
 #define VBAT_PWR_PIN GPIO_NUM_17
+
+/* Speaker amplifier enable driven by the ES8311 codec (components/codec_board/board_cfg.txt) */
+#define AUDIO_PA_PIN GPIO_NUM_46
```

### 5.5 `main/audio_ctrl.hpp` / `audio_ctrl.cpp`

The playback task now goes through the BSP session API and holds the codec lock for the
whole file, which is what pauses the microphone. A `play()` entry point lets the wake task
request the ack sound without going through MQTT.

```diff
--- a/main/audio_ctrl.hpp
+++ b/main/audio_ctrl.hpp
@@
 #pragma once
 
+#include <cstdint>
 #include <string>
@@
 // Download completion handler (registered for DownloadTarget::AUDIO).
 void notify_downloaded(bool success, const std::string &filepath);
+
+void play(const char *filename, uint8_t volume);
 
 } // namespace audio_ctrl
```

```diff
--- a/main/audio_ctrl.cpp
+++ b/main/audio_ctrl.cpp
@@
 	audio_bsp_init();
-	esp_codec_dev_sample_info_t fs = {};
-	fs.sample_rate = 16000;
-	fs.channel = 2;
-	fs.bits_per_sample = 16;
-	esp_codec_dev_handle_t playback = get_playback_handle();
@@
 		ESP_LOGI(TAG, "Audio play: %s (vol=%d)", filename, volume);
-		esp_codec_dev_set_out_vol(playback, (float)volume);
 
 		if (strcmp(filename, "boot") == 0)
 		{
 			extern const uint8_t music_pcm_start[] asm("_binary_canon_pcm_start");
 			extern const uint8_t music_pcm_end[]   asm("_binary_canon_pcm_end");
 			size_t pcm_size = music_pcm_end - music_pcm_start;
 			uint8_t *pcm_ptr = (uint8_t *)music_pcm_start;
 
-			if (esp_codec_dev_open(playback, &fs) == ESP_CODEC_DEV_OK)
+			if (!audio_lock(1000))
+			{
+				ESP_LOGE(TAG, "Audio: codec busy, dropping playback");
+				continue;
+			}
+			if (audio_playback_begin(16000, 2))
 			{
+				audio_playback_set_vol(volume);
 				size_t written = 0;
 				while (written < pcm_size)
 				{
-					esp_codec_dev_write(playback, pcm_ptr + written, 256);
+					audio_playback_write(pcm_ptr + written, 256);
 					written += 256;
 				}
+				audio_playback_end();
 			}
-			esp_codec_dev_close(playback);
+			audio_unlock();
 			ESP_LOGI(TAG, "Boot sound playback complete");
 		}
 		else
@@
-			if (esp_codec_dev_open(playback, &fs) == ESP_CODEC_DEV_OK)
+			if (!audio_lock(1000))
+			{
+				ESP_LOGE(TAG, "Audio: codec busy, dropping %s", filename);
+				fclose(f);
+				continue;
+			}
+			if (audio_playback_begin(16000, 2))
 			{
+				audio_playback_set_vol(volume);
 				uint8_t buf[1024];
 				size_t bytes_read;
 				while ((bytes_read = fread(buf, 1, sizeof(buf), f)) > 0)
 				{
-					esp_codec_dev_write(playback, buf, bytes_read);
+					audio_playback_write(buf, bytes_read);
 				}
+				audio_playback_end();
 			}
-			esp_codec_dev_close(playback);
+			audio_unlock();
 			fclose(f);
 			ESP_LOGI(TAG, "Audio file playback complete: %s", file_path.c_str());
 		}
 	}
 }
+
+void audio_ctrl::play(const char *filename, uint8_t volume)
+{
+	if (filename == NULL || filename[0] == '\0') {
+		return;
+	}
+	{
+		std::lock_guard<std::mutex> lock(s_state.mutex);
+		strncpy(s_state.filename, filename, sizeof(s_state.filename) - 1);
+		s_state.filename[sizeof(s_state.filename) - 1] = '\0';
+		s_state.volume = volume;
+		s_state.active = true;
+	}
+	if (s_audio_task_handle != NULL) {
+		xTaskNotifyGive(s_audio_task_handle);
+	}
+}
```

The duplicated filename/volume/notify block in `handle_command()` and
`notify_downloaded()` collapses into `play()` as a follow-up cleanup (not required for
this feature). After this change `#include "codec_init.h"` in `audio_ctrl.cpp` is unused
and can go; `audio_bsp.h` is the only audio include left.

### 5.6 `main/wake_ctrl.hpp` (new)

```cpp
#pragma once

#include <cstdint>

#include "cJSON.h"

// Always-on wake-word subsystem: owns the ESP-SR WakeNet9 model, streams the
// ES8311 microphone through it, and reacts to detections.

namespace wake_ctrl {

void init(void);
void start(void);
void stop(void);

void handle_command(const char *payload);

void status_serialize(cJSON *obj);
void status_apply(cJSON *obj);

bool listening(void);
const char *model_name_get(void);
float threshold_get(void);

} // namespace wake_ctrl
```

### 5.7 `main/wake_ctrl.cpp` (new)

```cpp
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "cJSON.h"

#include "model_path.h"
#include "esp_wn_iface.h"
#include "esp_wn_models.h"

#include "audio_bsp.h"
#include "audio_ctrl.hpp"
#include "app_common.hpp"
#include "config_store.hpp"
#include "identity.hpp"
#include "led_ctrl.hpp"
#include "mqtt_io.hpp"
#include "wake_ctrl.hpp"

static const char *TAG = "wake";

static const char *SR_MODEL_PATH = "/sdcard/srmodel";
static const uint32_t MODEL_RETRY_MS   = 60000;
static const uint32_t COOLDOWN_MS      = 1500;
static const uint32_t FRAME_TIMEOUT_MS = 200;

static struct {
	bool enabled;
	char model[32];
	char mode[16];
	float threshold;
	char ack_sound[64];
	uint8_t ack_volume;
	char led_color[16];
	uint8_t led_brightness;
	uint16_t led_duration_s;
	bool listening;
} s_wake = {
	.enabled = true,
	.model = "hiesp",
	.mode = "3ch95",
	.threshold = 0.635f,
	.ack_sound = "",
	.ack_volume = 70,
	.led_color = "#00E5FF",
	.led_brightness = 60,
	.led_duration_s = 2,
	.listening = false,
};

static srmodel_list_t *s_models = NULL;
static esp_wn_iface_t *s_wn = NULL;
static model_iface_data_t *s_md = NULL;
static int16_t *s_mono = NULL;
static int16_t *s_frame = NULL;
static int s_chunk = 512;
static int s_channels = 1;
static int s_rate = 16000;
static volatile bool s_reload = false;
static TaskHandle_t s_task = NULL;

static det_mode_t mode_from_string(const char *mode)
{
	if (strcmp(mode, "3ch90") == 0) return DET_MODE_3CH_90;
	if (strcmp(mode, "2ch95") == 0) return DET_MODE_2CH_95;
	if (strcmp(mode, "2ch90") == 0) return DET_MODE_2CH_90;
	if (strcmp(mode, "95")    == 0) return DET_MODE_95;
	return DET_MODE_3CH_95;
}

static float clampf(float value, float lo, float hi)
{
	return value < lo ? lo : (value > hi ? hi : value);
}

static float rms_dbfs(const int16_t *samples, int count)
{
	double acc = 0.0;
	for (int i = 0; i < count; i++) {
		double v = samples[i] / 32768.0;
		acc += v * v;
	}
	double rms = sqrt(acc / (count > 0 ? count : 1));
	return rms > 0.0 ? (float)(20.0 * log10(rms)) : -99.0f;
}

static void model_release(void)
{
	if (s_wn != NULL && s_md != NULL) {
		s_wn->destroy(s_md);
	}
	s_md = NULL;
	s_wn = NULL;
	if (s_models != NULL) {
		esp_srmodel_deinit(s_models);
		s_models = NULL;
	}
	free(s_mono);
	free(s_frame);
	s_mono = NULL;
	s_frame = NULL;
	s_wake.listening = false;
}

static bool model_load(void)
{
	srmodel_list_t *models = esp_srmodel_init(SR_MODEL_PATH);
	if (models == NULL) {
		ESP_LOGE(TAG, "no models under %s", SR_MODEL_PATH);
		return false;
	}
	char *name = esp_srmodel_filter(models, ESP_WN_PREFIX, s_wake.model);
	if (name == NULL) {
		ESP_LOGE(TAG, "no wake word matching '%s'", s_wake.model);
		esp_srmodel_deinit(models);
		return false;
	}
	esp_wn_iface_t *wn = esp_wn_handle_from_name(name);
	if (wn == NULL) {
		esp_srmodel_deinit(models);
		return false;
	}
	model_iface_data_t *md = wn->create(name, mode_from_string(s_wake.mode));
	if (md == NULL) {
		ESP_LOGE(TAG, "create(%s, %s) failed", name, s_wake.mode);
		esp_srmodel_deinit(models);
		return false;
	}

	s_chunk = wn->get_samp_chunksize(md);
	s_rate = wn->get_samp_rate(md);
	s_channels = wn->get_channel_num(md);
	s_mono = (int16_t *)calloc(s_chunk, sizeof(int16_t));
	s_frame = (int16_t *)calloc(s_chunk * s_channels, sizeof(int16_t));
	if (s_mono == NULL || s_frame == NULL) {
		model_release();
		return false;
	}

	int words = wn->get_word_num(md);
	for (int i = 1; i <= words; i++) {
		char *word = wn->get_word_name(md, i);
		ESP_LOGI(TAG, "word[%d] = %s", i, word != NULL ? word : "?");
	}
	wn->set_det_threshold(md, s_wake.threshold, 1);

	s_models = models;
	s_wn = wn;
	s_md = md;

	ESP_LOGI(TAG, "ready: model=%s rate=%d chunk=%d channels=%d words=%d thr=%.3f",
			 name, s_rate, s_chunk, s_channels, words, s_wake.threshold);
	return true;
}

static void publish_detection(int channel, float level_dbfs)
{
	cJSON *root = cJSON_CreateObject();
	if (root == NULL) {
		return;
	}
	cJSON_AddStringToObject(root, "event", "wake");
	cJSON_AddStringToObject(root, "word", "Hi,ESP");
	cJSON_AddStringToObject(root, "model", s_wake.model);
	cJSON_AddNumberToObject(root, "channel", channel);
	cJSON_AddNumberToObject(root, "threshold", s_wake.threshold);
	cJSON_AddNumberToObject(root, "level_dbfs", level_dbfs);
	cJSON_AddNumberToObject(root, "uptime_ms", (double)(esp_timer_get_time() / 1000));

	char *payload = cJSON_PrintUnformatted(root);
	if (payload != NULL) {
		app::mqtt_publish(identity_topic_evt_wakeup(), payload, 1, 0);
		free(payload);
	}
	cJSON_Delete(root);
}

static void led_flash(void)
{
	char payload[192];
	snprintf(payload, sizeof(payload),
			 "{\"enable\":true,\"pattern\":\"solid_color\",\"color\":\"%s\","
			 "\"brightness\":%u,\"duration\":%u,\"persist\":false}",
			 s_wake.led_color, s_wake.led_brightness, s_wake.led_duration_s);
	led_ctrl::handle_rgb_command(payload);
}

static void wake_task(void *arg)
{
	audio_bsp_init();
	vTaskDelay(pdMS_TO_TICKS(500));

	int64_t retry_at = 0;
	uint32_t frames = 0;

	for (;;)
	{
		if (s_reload) {
			s_reload = false;
			if (audio_lock(FRAME_TIMEOUT_MS)) {
				audio_record_end();
				audio_unlock();
			}
			model_release();
			retry_at = 0;
		}

		if (!s_wake.enabled) {
			s_wake.listening = false;
			vTaskDelay(pdMS_TO_TICKS(500));
			continue;
		}

		if (s_wn == NULL) {
			int64_t now = esp_timer_get_time() / 1000;
			if (now < retry_at) {
				vTaskDelay(pdMS_TO_TICKS(500));
				continue;
			}
			retry_at = now + MODEL_RETRY_MS;
			if (!model_load()) {
				continue;
			}
		}
		s_wake.listening = true;

		if (!audio_lock(FRAME_TIMEOUT_MS)) {
			continue;
		}
		int bytes = -1;
		if (audio_record_begin(s_rate, 1)) {
			bytes = audio_record_read(s_mono, s_chunk * sizeof(int16_t));
		}
		audio_unlock();

		if (bytes < 0) {
			vTaskDelay(pdMS_TO_TICKS(20));
			continue;
		}

		if (s_channels == 1) {
			memcpy(s_frame, s_mono, s_chunk * sizeof(int16_t));
		} else {
			for (int i = 0; i < s_chunk; i++) {
				for (int c = 0; c < s_channels; c++) {
					s_frame[(i * s_channels) + c] = s_mono[i];
				}
			}
		}

		wakenet_state_t state = s_wn->detect(s_md, s_frame);
		float level = rms_dbfs(s_mono, s_chunk);

		if (++frames % 50 == 0) {
			ESP_LOGD(TAG, "listening, level=%.1f dBFS", level);
		}
		if (state != WAKENET_DETECTED) {
			continue;
		}

		int channel = s_wn->get_triggered_channel(s_md);
		s_wn->clean(s_md);
		ESP_LOGI(TAG, "WAKE 'Hi,ESP' ch=%d level=%.1f dBFS", channel, level);

		publish_detection(channel, level);
		led_flash();
		audio_ctrl::play(s_wake.ack_sound, s_wake.ack_volume);

		vTaskDelay(pdMS_TO_TICKS(COOLDOWN_MS));
	}
}

void wake_ctrl::init(void)
{
	mqtt_register_cmd(identity_topic_cmd_wakeup(), wake_ctrl::handle_command);
}

void wake_ctrl::start(void)
{
	if (s_task == NULL) {
		xTaskCreatePinnedToCore(wake_task, "wake", 8192, NULL, 4, &s_task, 0);
	}
}

void wake_ctrl::stop(void)
{
	if (s_task != NULL) {
		vTaskDelete(s_task);
		s_task = NULL;
		s_wake.enabled = false;
	}
}

void wake_ctrl::handle_command(const char *payload)
{
	ESP_LOGI(TAG, "Wake command received");

	cJSON *json = cJSON_Parse(payload);
	if (json == NULL) {
		ESP_LOGE(TAG, "Wake: invalid JSON");
		return;
	}

	bool reload = false;

	cJSON *enabled = cJSON_GetObjectItemCaseSensitive(json, "enabled");
	if (cJSON_IsBool(enabled)) {
		s_wake.enabled = cJSON_IsTrue(enabled);
	}

	cJSON *model = cJSON_GetObjectItemCaseSensitive(json, "model");
	if (cJSON_IsString(model) && model->valuestring != NULL) {
		if (strcmp(s_wake.model, model->valuestring) != 0) {
			strncpy(s_wake.model, model->valuestring, sizeof(s_wake.model) - 1);
			s_wake.model[sizeof(s_wake.model) - 1] = '\0';
			reload = true;
		}
	}

	cJSON *mode = cJSON_GetObjectItemCaseSensitive(json, "mode");
	if (cJSON_IsString(mode) && mode->valuestring != NULL) {
		if (strcmp(s_wake.mode, mode->valuestring) != 0) {
			strncpy(s_wake.mode, mode->valuestring, sizeof(s_wake.mode) - 1);
			s_wake.mode[sizeof(s_wake.mode) - 1] = '\0';
			reload = true;
		}
	}

	cJSON *threshold = cJSON_GetObjectItemCaseSensitive(json, "threshold");
	if (cJSON_IsNumber(threshold)) {
		float value = clampf((float)threshold->valuedouble, 0.4f, 0.9999f);
		if (value != s_wake.threshold) {
			s_wake.threshold = value;
			reload = true;
		}
	}

	cJSON *ack = cJSON_GetObjectItemCaseSensitive(json, "ack_sound");
	if (cJSON_IsString(ack) && ack->valuestring != NULL) {
		strncpy(s_wake.ack_sound, ack->valuestring, sizeof(s_wake.ack_sound) - 1);
		s_wake.ack_sound[sizeof(s_wake.ack_sound) - 1] = '\0';
	}

	cJSON *ack_volume = cJSON_GetObjectItemCaseSensitive(json, "ack_volume");
	if (cJSON_IsNumber(ack_volume)) {
		s_wake.ack_volume = (uint8_t)clampf((float)ack_volume->valuedouble, 0.0f, 100.0f);
	}

	cJSON *led_color = cJSON_GetObjectItemCaseSensitive(json, "led_color");
	if (cJSON_IsString(led_color) && led_color->valuestring != NULL) {
		strncpy(s_wake.led_color, led_color->valuestring, sizeof(s_wake.led_color) - 1);
		s_wake.led_color[sizeof(s_wake.led_color) - 1] = '\0';
	}

	cJSON *led_brightness = cJSON_GetObjectItemCaseSensitive(json, "led_brightness");
	if (cJSON_IsNumber(led_brightness)) {
		s_wake.led_brightness = (uint8_t)clampf((float)led_brightness->valuedouble, 0.0f, 100.0f);
	}

	cJSON *led_duration = cJSON_GetObjectItemCaseSensitive(json, "led_duration_s");
	if (cJSON_IsNumber(led_duration)) {
		s_wake.led_duration_s = (uint16_t)clampf((float)led_duration->valuedouble, 0.0f, 3600.0f);
	}

	cJSON_Delete(json);

	if (reload) {
		s_reload = true;
	}
	config_store_save();
}

void wake_ctrl::status_serialize(cJSON *obj)
{
	cJSON_AddBoolToObject(obj, "enabled", s_wake.enabled);
	cJSON_AddStringToObject(obj, "model", s_wake.model);
	cJSON_AddStringToObject(obj, "mode", s_wake.mode);
	cJSON_AddNumberToObject(obj, "threshold", s_wake.threshold);
	cJSON_AddStringToObject(obj, "ack_sound", s_wake.ack_sound);
	cJSON_AddNumberToObject(obj, "ack_volume", s_wake.ack_volume);
	cJSON_AddStringToObject(obj, "led_color", s_wake.led_color);
	cJSON_AddNumberToObject(obj, "led_brightness", s_wake.led_brightness);
	cJSON_AddNumberToObject(obj, "led_duration_s", s_wake.led_duration_s);
	cJSON_AddBoolToObject(obj, "listening", s_wake.listening);
}

void wake_ctrl::status_apply(cJSON *obj)
{
	cJSON *enabled = cJSON_GetObjectItemCaseSensitive(obj, "enabled");
	if (cJSON_IsBool(enabled)) {
		s_wake.enabled = cJSON_IsTrue(enabled);
	}

	cJSON *model = cJSON_GetObjectItemCaseSensitive(obj, "model");
	if (cJSON_IsString(model) && model->valuestring != NULL) {
		strncpy(s_wake.model, model->valuestring, sizeof(s_wake.model) - 1);
		s_wake.model[sizeof(s_wake.model) - 1] = '\0';
	}

	cJSON *mode = cJSON_GetObjectItemCaseSensitive(obj, "mode");
	if (cJSON_IsString(mode) && mode->valuestring != NULL) {
		strncpy(s_wake.mode, mode->valuestring, sizeof(s_wake.mode) - 1);
		s_wake.mode[sizeof(s_wake.mode) - 1] = '\0';
	}

	cJSON *threshold = cJSON_GetObjectItemCaseSensitive(obj, "threshold");
	if (cJSON_IsNumber(threshold)) {
		s_wake.threshold = clampf((float)threshold->valuedouble, 0.4f, 0.9999f);
	}

	cJSON *ack = cJSON_GetObjectItemCaseSensitive(obj, "ack_sound");
	if (cJSON_IsString(ack) && ack->valuestring != NULL) {
		strncpy(s_wake.ack_sound, ack->valuestring, sizeof(s_wake.ack_sound) - 1);
		s_wake.ack_sound[sizeof(s_wake.ack_sound) - 1] = '\0';
	}

	cJSON *ack_volume = cJSON_GetObjectItemCaseSensitive(obj, "ack_volume");
	if (cJSON_IsNumber(ack_volume)) {
		s_wake.ack_volume = (uint8_t)clampf((float)ack_volume->valuedouble, 0.0f, 100.0f);
	}

	cJSON *led_color = cJSON_GetObjectItemCaseSensitive(obj, "led_color");
	if (cJSON_IsString(led_color) && led_color->valuestring != NULL) {
		strncpy(s_wake.led_color, led_color->valuestring, sizeof(s_wake.led_color) - 1);
		s_wake.led_color[sizeof(s_wake.led_color) - 1] = '\0';
	}

	cJSON *led_brightness = cJSON_GetObjectItemCaseSensitive(obj, "led_brightness");
	if (cJSON_IsNumber(led_brightness)) {
		s_wake.led_brightness = (uint8_t)clampf((float)led_brightness->valuedouble, 0.0f, 100.0f);
	}

	cJSON *led_duration = cJSON_GetObjectItemCaseSensitive(obj, "led_duration_s");
	if (cJSON_IsNumber(led_duration)) {
		s_wake.led_duration_s = (uint16_t)clampf((float)led_duration->valuedouble, 0.0f, 3600.0f);
	}

	ESP_LOGI(TAG, "Restored wake config: enabled=%d model=%s mode=%s thr=%.3f",
			 s_wake.enabled, s_wake.model, s_wake.mode, s_wake.threshold);
}

bool wake_ctrl::listening(void)
{
	return s_wake.listening;
}

const char *wake_ctrl::model_name_get(void)
{
	return s_wake.model;
}

float wake_ctrl::threshold_get(void)
{
	return s_wake.threshold;
}
```

Notes on this module:

* The capture buffer is allocated from the size the model asks for
  (`get_samp_chunksize()` × `get_channel_num()`), so nothing is hardcoded.
* `s_channels > 1` duplicates the single microphone channel into an interleaved buffer.
  That branch is the OQ-1 resolution point: if P1 shows the model wants real multiple
  channels, create it with `DET_MODE_95` (`s_channels == 1`) instead.
* `detect()` runs **outside** the codec lock — it is pure CPU, so playback is never
  delayed by detection.
* `s_reload` is how a `cmd/wakeup` change to `model`, `mode` or `threshold` takes effect
  without a reboot; the next `threshold`-only change also needs a reload because
  `set_det_threshold()` is applied at create time.

### 5.8 `main/CMakeLists.txt`

```diff
 idf_component_register(SRCS "app_common.cpp" "app_main.cpp" "audio_ctrl.cpp" "config_store.cpp"
                     "display_ctrl.cpp" "download_mgr.cpp" "identity.cpp" "led_ctrl.cpp"
                     "mqtt_io.cpp" "ota_ctrl.cpp" "provisioning.cpp" "rgb_color.cpp"
-                    "status_ctrl.cpp" "ui_port.cpp" "data_downloader.cpp" "wifi.c" "wifi_no.c"
+                    "status_ctrl.cpp" "ui_port.cpp" "data_downloader.cpp" "wake_ctrl.cpp" "wifi.c" "wifi_no.c"
                     INCLUDE_DIRS "./"
                     REQUIRES led_strip sdcard_manager esp_http_client user_app nvs_flash mqtt json mqtt_logger audio_bsp app_update esp_app_format network_provisioning qrcode esp_timer esp_wifi esp_netif esp_event
-                    PRIV_REQUIRES codec_board
+                    PRIV_REQUIRES codec_board espressif__esp-sr
 )
```

### 5.9 `main/app_main.cpp`

```diff
 #include "status_ctrl.hpp"
 #include "ui_port.hpp"
+#include "wake_ctrl.hpp"
@@
 	ota_ctrl::init();
 	status_ctrl::init();
+	wake_ctrl::init();
@@
 	xTaskCreate(ui_overlay_task, "ui_overlay", 4096, NULL, 4, NULL);
 	audio_ctrl::start();
+	// After the SD mount (model + ack sound live there) and after the audio task
+	// owns its side of the shared codec.
+	wake_ctrl::start();
```

### 5.10 `main/identity.hpp` / `identity.cpp`

```diff
--- a/main/identity.hpp
+++ b/main/identity.hpp
@@
 const char *identity_topic_evt_status(void);
+const char *identity_topic_cmd_wakeup(void);
+const char *identity_topic_evt_wakeup(void);
```

```diff
--- a/main/identity.cpp
+++ b/main/identity.cpp
@@
 static char s_mqtt_evt_status_topic[MQTT_TOPIC_MAX_LEN];
+static char s_mqtt_evt_wakeup_topic[MQTT_TOPIC_MAX_LEN];
+static char s_mqtt_cmd_wakeup_topic[MQTT_TOPIC_MAX_LEN];
@@
 	snprintf(s_mqtt_evt_status_topic, sizeof(s_mqtt_evt_status_topic),
 			 "thelink/%s/evt/status", s_device_id);
+	snprintf(s_mqtt_evt_wakeup_topic, sizeof(s_mqtt_evt_wakeup_topic),
+			 "thelink/%s/evt/wakeup", s_device_id);
+	snprintf(s_mqtt_cmd_wakeup_topic, sizeof(s_mqtt_cmd_wakeup_topic),
+			 "thelink/%s/cmd/wakeup", s_device_id);
@@
 	ESP_LOGI("DEVICE", "Status evt topic: %s", s_mqtt_evt_status_topic);
+	ESP_LOGI("DEVICE", "Wake cmd topic: %s", s_mqtt_cmd_wakeup_topic);
+	ESP_LOGI("DEVICE", "Wake evt topic: %s", s_mqtt_evt_wakeup_topic);
@@
 const char *identity_topic_evt_status(void)
 {
 	return s_mqtt_evt_status_topic;
 }
+
+const char *identity_topic_evt_wakeup(void)
+{
+	return s_mqtt_evt_wakeup_topic;
+}
+
+const char *identity_topic_cmd_wakeup(void)
+{
+	return s_mqtt_cmd_wakeup_topic;
+}
```

### 5.11 `main/config_store.cpp` and `main/status_ctrl.cpp`

```diff
--- a/main/config_store.cpp
+++ b/main/config_store.cpp
@@
 #include "led_ctrl.hpp"
+#include "wake_ctrl.hpp"
@@
 	// Add LED pattern state as a structured object
 	{
 		cJSON *led = cJSON_CreateObject();
 		led_ctrl::status_serialize(led);
 		cJSON_AddItemToObject(root, "led", led);
 	}
+
+	// Add wake-word configuration
+	{
+		cJSON *wake = cJSON_CreateObject();
+		wake_ctrl::status_serialize(wake);
+		cJSON_AddItemToObject(root, "wake", wake);
+	}
@@
 			// Parse and apply LED notification parameters
 			cJSON *led_item = cJSON_GetObjectItemCaseSensitive(json, "led");
@@
 			}
+
+			// Parse and apply wake-word parameters
+			cJSON *wake_item = cJSON_GetObjectItemCaseSensitive(json, "wake");
+			if (cJSON_IsObject(wake_item))
+			{
+				wake_ctrl::status_apply(wake_item);
+			}
```

`wake_ctrl::status_serialize()` emits `enabled`, `model`, `mode`, `threshold`,
`ack_sound`, `ack_volume`, `led_color`, `led_brightness`, `led_duration_s` and
`listening`; `status_apply()` accepts the same keys except `listening`, which is a
transient runtime field — the value `config_store_save()` happens to write into
`config.json` is never applied back. The wake task never calls `config_store_save()`.

```diff
--- a/main/status_ctrl.cpp
+++ b/main/status_ctrl.cpp
@@
 #include "status_ctrl.hpp"
+#include "wake_ctrl.hpp"
@@
 	cJSON_AddStringToObject(root, "rgb_pattern", led_ctrl::pattern_get());
+
+	{
+		cJSON *wake = cJSON_CreateObject();
+		wake_ctrl::status_serialize(wake);
+		cJSON_AddItemToObject(root, "wake", wake);
+	}
```

### 5.12 `scripts/export_wake_model.py` (new)

Copies the bundled model to the SD card and prints the verification checklist.

```python
#!/usr/bin/env python3
"""Copy a bundled ESP-SR wake-word model from managed_components onto the SD card."""

import argparse
import shutil
import sys
from pathlib import Path

MODEL_SUBDIR = Path("model/wakenet_model")


def find_component_root(project: Path) -> Path:
    candidates = [
        project / "managed_components" / "espressif__esp-sr",
        project / "components" / "esp-sr",
    ]
    for candidate in candidates:
        if (candidate / MODEL_SUBDIR).is_dir():
            return candidate
    raise SystemExit("esp-sr component not found; run idf.py reconfigure first")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="wn9_hiesp")
    parser.add_argument("--out", default="/media/$USER/thelink/srmodel")
    parser.add_argument("--project", default=str(Path(__file__).resolve().parent.parent))
    args = parser.parse_args()

    src = find_component_root(Path(args.project)) / MODEL_SUBDIR / args.model
    if not src.is_dir():
        raise SystemExit(f"model {args.model} not found at {src}")

    dst = Path(args.out) / args.model
    dst.mkdir(parents=True, exist_ok=True)
    for name in ("_MODEL_INFO_", "wn9_data", "wn9_index"):
        shutil.copy2(src / name, dst / name)
        print(f"{src / name} -> {dst / name}")

    print("\nVerify the card contains:")
    print(f"  {args.out}/wn9_hiesp/_MODEL_INFO_")
    print(f"  {args.out}/wn9_hiesp/wn9_data")
    print(f"  {args.out}/wn9_hiesp/wn9_index")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 5.13 `Readme.md`

```diff
-- microphone (available for future projects)
+- microphone (always-on wake word "Hi,ESP" — see [feature_wake.md](feature_wake.md))
```

### 5.14 Deliberately not touched

* `partitions.csv`, `partitions_dev.csv` — the model is on the SD card, and
  `esp-sr/CMakeLists.txt` skips model flashing when no `model` partition exists (§3.2).
* `scripts/flash_all.py` — nothing new is written to flash.
* `sdkconfig.prod`, `scripts/build.py` — both profiles get the feature; no per-profile
  difference.
* `components/board_power_bsp` — the audio rail is already enabled at boot
  (`user_app.cpp:26`); power management is §8, not this feature.
* `main/audio_ctrl.cpp` cleanup of the duplicated play-state blocks (deferred).

---

## 6. Phases and verification

| Phase | Work | Done when |
| --- | --- | --- |
| **P0** | Land the §5.3 BSP rework (single handle, session enum, PA control, idempotent init), then probe the mic: log RMS dBFS every 500 ms | dBFS in a sane range at 0.3 m; PA stays silent while listening; `audio_pa_set(false)` is what keeps it quiet; the boot sound still plays |
| **P1** | Add ESP-SR, export the model, load it, log `get_samp_chunksize()`, `get_channel_num()`, `get_samp_rate()`, `get_word_num()` | model loads from `/sdcard/srmodel`; word list shows `Hi,ESP`; removing the model directory produces a warning + 60 s retry, not a boot loop |
| **P2** | Feed frames to `detect()`, log detections and detection latency | "Hi,ESP" at 1 m triggers in ~1/10 attempts; 30 min of ambient room audio produces no detections (record the miss rate) |
| **P3** | Event + LED flash + ack sound, codec arbitration under playback | MQTT event received by the backend; LED flashes; ack sound plays; the mic is silent and PA-off during playback; playback latency ≤ ~50 ms |
| **P4** | Persistence, `cmd/wakeup`, `status` payload, README | config survives reboot; `cmd/wakeup {"enabled":false}` stops listening without a reboot |

---

## 7. Open questions

* **OQ-1 `wn9_hiesp` channel count.** `esp_wn_iface.h` defines `DET_MODE_3CH_*` modes, and the
  ESP-SR docs list `wn9_hiesp` as a 3-channel model. If `get_channel_num()` returns 3 on a
  one-microphone board, either duplicate the mono frame into 3 interleaved channels or
  create the model with `DET_MODE_95`. P1 logs the value; §5.7 branches on it.
* **OQ-2 Frame size vs. sample rate.** `get_samp_chunksize()` is authoritative; if it is not
  512 samples / 16 kHz the capture fs in §5.7 must follow `get_samp_rate()`.
* **OQ-3 Does `esp_codec_dev_open()` on the shared `IN_OUT` handle accept a mono fs while
  playback uses stereo?** P0 verifies by opening 16 kHz/1 ch for capture and
  16 kHz/2 ch for playback on the same handle, and playing the boot sound in between.
* **OQ-4 PSRAM capacity.** Confirm from the vendor spec that 8 MB is present; the model
  needs ~350 KB in PSRAM and `DET_MODE_*_90` (flash-resident) is not an option on this board.
* **OQ-5 Power budget.** An always-on codec + mic will dominate battery life. Measure
  current with the mic open and decide whether a duty-cycle or VAD gate is required (§8).

---

## 8. Deferred work

* **Full AFE** (`esp_afe_feed` with AEC/VAD/NS) if false alarms become a problem, or if
  wake-while-playing is ever wanted. Cost: more RAM/PSRAM and a threshold API on the AFE
  instead of the model.
* **Barge-in / AEC:** not possible without the full AFE.
* **Duty cycling:** `wake.threshold` and an optional VAD gate would allow shutting the
  record path between phrases.
* **Power management:** audio rail switch-off (`Audio_PWR_PIN = GPIO42`,
  `components/user_app/user_app.cpp:26`) between duty cycles.
* **Custom "Hi Link" model:** see §10.
* **Multiple models at once:** the standalone interface handles one model per instance;
  `esp_srmodel_filter()` plus a second `create()` would be needed to listen for two words.
  Out of scope until a second bundled word is actually wanted.

---

## 9. References

* ESP-SR Wake Word Engine docs —
  <https://docs.espressif.com/projects/esp-sr/en/latest/esp32s3/wake_word_engine/README.html>
* `esp_wn_iface.h` (det modes, threshold setter, channel/chunk queries) —
  <https://github.com/espressif/esp-sr/blob/master/include/esp32s3/esp_wn_iface.h>
* `esp-sr/CMakeLists.txt` (model partition / `srmodels.bin` logic) —
  <https://github.com/espressif/esp-sr/blob/master/CMakeLists.txt>
* Model storage from SD card —
  <https://docs.espressif.com/projects/esp-sr/en/latest/esp32s3/flash_model/README.html>

---

## 10. Custom wake word ("Hi Link") — not in this phase

Renaming the `_MODEL_INFO_` display string does **not** retrain the network: the model
still recognises "Hi,ESP". A genuinely custom word needs either

* the free community route (community voice requests, tracked in
  <https://github.com/espressif/esp-sr/issues/88>), or
* Espressif's paid customization service
  (<https://docs.espressif.com/projects/esp-sr/en/latest/esp32s3/wake_word_engine/ESP_Wake_Words_Customization.html>).

Either way the model would drop into the same `/sdcard/srmodel/<name>/` layout and
`wake.model` would select it at runtime — no code change beyond the export script.