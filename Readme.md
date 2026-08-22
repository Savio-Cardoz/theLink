
## TheLink ESP32-S3

MQTT-controlled embedded device driving an e-paper display, RGB LED strip, and audio output.

### Requirements

- ESP-IDF v5.x with ESP-IDF shell environment
- LVGL Minimal Configuration enabled (`CONFIG_LV_USE_PERF_MONITOR` OFF to save heap)
- MQTT v5 broker (default: `mqtt://broker.emqx.io`)
- SD card (FAT32) mounted at `/sdcard`

### Build & Flash

```bash
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

---

## MQTT Topics

All topics are per-device, derived from the last 3 bytes of the factory MAC address.

| Topic | Direction | QoS | Purpose |
|-------|-----------|-----|---------|
| `thelink/{device_id}/cmd/display` | Subscribe | 1 | Send image display commands |
| `thelink/{device_id}/cmd/rgb` | Subscribe | 1 | Send RGB LED pattern commands |
| `thelink/{device_id}/cmd/audio` | Subscribe | 1 | Send audio playback commands |
| `thelink/{device_id}/cmd/notification` | Subscribe | 1 | Send LED notification commands |
| `thelink/{device_id}/cmd/log` | Subscribe | 1 | Send logger control commands |
| `thelink/{device_id}/evt/log` | Publish | 0 | Device log output (JSON) |
| `company/command` | Subscribe | 2 | Legacy topic (backward compatible) |

Device ID format: `thelink-XXYYZZ` (e.g. `thelink-0A1B2C`)

---

## Command Schemas

### Display (`thelink/{device_id}/cmd/display`)

Downloads an image from a URL, saves it to SD card, and renders it on the e-paper display.

```json
{
  "download": "http://example.com/image.i8",
  "filename": "image.i8"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `download` | string | Yes | HTTP(S) URL to download the image from |
| `filename` | string | Yes | Target filename on SD card (saved to `/sdcard/{filename}`) |

Image format: LVGL I8 (indexed 8-bit, 200x200, with 256-color palette).

### RGB LED (`thelink/{device_id}/cmd/rgb`)

Sets the LED strip pattern.

```json
{
  "pattern": "scanner"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern` | string | Yes | Pattern name (see table below) |

**Available patterns:**

| Pattern | Description |
|---------|-------------|
| `solid_color` | Single static color (default when inactive) |
| `rainbow_cycle` | Smooth rainbow cycle across all LEDs |
| `theater_chase` | Theater-style chasing light effect |
| `color_wipe` | Sequential color fill |
| `scanner` | Scanning light sweep back and forth |
| `fade` | Breathing fade effect |

### Audio (`thelink/{device_id}/cmd/audio`)

Queues an audio file for playback.

```json
{
  "filename": "alert.wav",
  "volume": 80
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `filename` | string | Yes | Audio file path on SD card |
| `volume` | number | No | Playback volume 0-100 |

### Notification (`thelink/{device_id}/cmd/notification`)

Activates an LED pattern as a notification alert.

```json
{
  "message": "scanner"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `message` | string | Yes | Pattern name (same values as RGB `pattern` field) |

### Log Control (`thelink/{device_id}/cmd/log`)

Controls the remote log level filter. Serial output is unaffected.

```json
{
  "action": "set_level",
  "level": "debug"
}
```

```json
{
  "action": "get_level"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | Yes | `"set_level"` or `"get_level"` |
| `level` | string | For `set_level` | `"error"`, `"warn"`, `"info"`, `"debug"`, `"verbose"`, or `"none"` |

---

## Event Output

### Log Events (`thelink/{device_id}/evt/log`)

Published as JSON with QoS 0:

```json
{
  "device_id": "thelink-0A1B2C",
  "level": "info",
  "tag": "app",
  "msg": "Display download complete"
}
```

---

## Legacy Topic

The device also subscribes to `company/command` (QoS 2) for backward compatibility. Messages on this topic use the old format:

```json
{
  "type": "display",
  "data": {
    "download": "http://example.com/image.i8",
    "filename": "image.i8"
  }
}
```

Supported `type` values: `"display"`, `"notification"`.

---

## Configuration

Build-time options in `menuconfig` (`Example Configuration`):

| Option | Default | Description |
|--------|---------|-------------|
| `CONFIG_BROKER_URL` | `mqtt://broker.emqx.io` | MQTT broker address |
| `CONFIG_COMMAND_TOPIC` | `company/command` | Legacy command topic |

---

## Version History

### v0.3.0
- Per-subsystem MQTT topics with dedicated handlers
- Dispatch table architecture for topic-based command routing
- Removed legacy `instructions_t` state duplication
- JSON payload logging downgraded to DEBUG level
- Global MQTT client handle for future publish use

### v0.2.0
- RGB LED strip control via MQTT
- `RgbLedStrip` class with `runPattern()` interface
- Pattern selection via MQTT `notification` command

### v0.1.0
- MQTT v5 protocol support
- E-paper display image download and render
- Wi-Fi provisioning (BLE/SoftAP)
- SD card image storage