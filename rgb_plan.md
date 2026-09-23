# TheLink — RGB LED minute control over MQTT (schema + implementation plan)

Adds fine-grained control of the 16-pixel NeoPixel ring (`Adafruit_NeoPixelRing16`,
GPIO 2, RMT-driven via `RgbLedStrip<16>`) over the existing MQTT `cmd/rgb` topic.

## Schema

Topic stays `thelink/{device_id}/cmd/rgb` (subscribe, QoS 1). Payload becomes a
rich JSON object. All legacy messages (`{pattern}`, `{enable}`) keep working.

```json
{
  "enable": true,
  "pattern": "rainbow_cycle",
  "color": { "h": 210, "s": 100, "v": 60 },
  "brightness": 75,
  "speed": 40,
  "pixels": ["#FF0000", "#00FF00", null, "... up to 16 entries ..."],
  "duration": 30,
  "persist": true
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enable` | bool | — | Master on/off; `false` flushes the strip to zero immediately |
| `pattern` | string | keep | `off` \| `solid_color` \| `rainbow_cycle` \| `theater_chase` \| `color_wipe` \| `scanner` \| `fade` (add `"off"` mapping; unknown names fall back to `solid_color`) |
| `color` | string \| obj | keep | `"#RRGGBB"` (also bare `RRGGBB`), `{h,s,v}` (h 0–360, s/v 0–100), or `{r,g,b}` (0–255). Unified to HSV internally — fixes latent bug where `hue` was `uint8_t` (0–255) but `hsv2rgb` expects 0–359 |
| `brightness` | number | 100 | 0–100 global multiplier applied to the final rendered frame, incl. per-pixel |
| `speed` | number | 20 | Animation frame period in ms, clamped 5–5000; advances the pattern phase |
| `pixels` | array | nil | Up to 16 per-LED values; each entry is a hex string / `{r,g,b}` / `{h,s,v}` / `null` (skip). Overrides pattern rendering while present |
| `duration` | number | nil | Auto-off after N seconds (notification semantics); resets on every command |
| `persist` | bool | true | Whether to write the state to `/sdcard/config.json` |

### Status event — `thelink/{device_id}/evt/led` (publish, retained, QoS 1)

Published after every accepted `cmd/rgb` command (ack), on `MQTT_EVENT_CONNECTED`,
and on auto-off expiry. Canonical state mirror:

```json
{
  "active": true,
  "pattern": "rainbow_cycle",
  "color": { "h": 210, "s": 100, "v": 60 },
  "brightness": 75,
  "speed": 40,
  "pixels": ["#FF0000", null, "... 16 entries ..."],
  "cmd_id": 12
}
```

### Persistence — `/sdcard/config.json`

`led` becomes a structured object (was a string `"active"/"inactive"`). No
`duration` / `cmd_id` persisted (transient). Legacy string form still parsed on
load for backward compatibility.

```json
{
  "display": "/sdcard/image.i8",
  "led": {
    "active": true,
    "pattern": "rainbow_cycle",
    "color": { "h": 210, "s": 100, "v": 60 },
    "brightness": 75,
    "speed": 40,
    "pixels": ["#FF0000", null, "..."]
  }
}
```

## Execution plan

### 1. `components/led_strip/rgb_led_strip.h` — expand driver API
- [x] 1.1 Add `"off"` to `pattern_from_string`.
- [x] 1.2 Expose statics `hsv2rgb` / add `rgb2hsv` (single source of truth for conversions).
- [x] 1.3 Add public per-pixel + fill helpers: `setAllRgb`, `setPixelRgb`, `setPixelHsv`, `clear`, `count()`.
- [x] 1.4 Add `setBrightness` / `brightness()`; scale the frame at `flush()` so patterns and per-pixel both honour it without re-scaled compounding.

### 2. `main/main.cpp` — state model
- [x] 2.1 Extend `led_state_t`: `hue → uint16_t` (0–359), add `brightness`, `speed_ms`, `duration_ms`, `set_at_ms`, `has_pixels`, `pixels[LED_COUNT]` (`-1` = skip, else `0xRRGGBB`), `cmd_id`. Define `LED_COUNT = 16`.
- [x] 2.2 Add helper `pattern_to_string(rgb_pattern_t)` and `led_color_t` parser (`parse_led_color`: hex string / `{h,s,v}` / `{r,g,b}`).

### 3. `main/main.cpp` — command handler
- [x] 3.1 Rewrite `handle_rgb_command` to parse/validate all fields, clamp ranges, keep legacy `{pattern}`/`{enable}` behaviour, run persistence when `persist` (default true), then publish `evt/led`.

### 4. `main/main.cpp` — status events
- [x] 4.1 Add `s_mqtt_evt_led_topic` (+ init/log in `device_id_init`).
- [x] 4.2 Add `publish_led_event()` (retained JSON of canonical state); call on accepted commands, auto-off, and `MQTT_EVENT_CONNECTED`.

### 5. `main/main.cpp` — persistence
- [x] 5.1 `save_settings_to_json`: emit structured `led` object.
- [x] 5.2 `load_settings_from_json`: restore object (and old string form).

### 6. `main/main.cpp` — LED task
- [x] 6.1 Rewrite `led_test_task`: phase accumulator advanced by `speed_ms`, exact-colour `solid_color`, per-pixel override path, brightness applied at flush, `duration` auto-off (guarded, publish-once), OFF/inactive → clear.

### 7. Docs & build
- [x] 7.1 Update `Readme.md` RGB LED section (schema table, events, persistence).
- [x] 7.2 Build dev profile (`python3 scripts/build.py`) and fix errors.

## Progress log

2026-09-23 — plan created. Schema + execution plan confirmed with user
(Rich JSON on existing `cmd/rgb` · HSV/RGB/hex color · full scope incl.
persistence + `evt/led` status events). Beginning implementation.

2026-09-23 — implementation complete:
- Driver: `"off"` pattern, public per-pixel/fill helpers, `setBrightness` applied
  during `flush()` (no compounding), `hsv2rgb`/`rgb2hsv` conversions.
- `cmd/rgb` now accepts `enable`, `pattern` (incl. `off`), `color` (hex / hsv /
  rgb), `brightness`, `speed`, `pixels[16]`, `duration`, `persist`; legacy
  `{pattern}` / `{enable}` payloads still work.
- New retained `evt/led` status event (ack on command, on connect, on auto-off).
- `config.json` `led` persisted as a structured object (legacy string parsed).
- `led_test_task` rewritten: exact-color solid, phase animation at `speed`,
  per-pixel override, global brightness at flush, duration auto-off.
- `Readme.md` RGB LED section and MQTT topics table updated.
- Dev build (`python3 scripts/build.py`) — clean compile, no new warnings.