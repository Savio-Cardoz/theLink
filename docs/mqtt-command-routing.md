# MQTT command routing

The application routes commands by their **exact MQTT topic**. Subsystems register a topic-to-function mapping during boot; after Wi-Fi is ready, the MQTT client subscribes to every registered topic. For each inbound `MQTT_EVENT_DATA`, the dispatcher copies the payload, looks up the topic in the map, and invokes the selected handler synchronously in the MQTT event callback.

## High-level design

The MQTT layer acts as a topic-based router: subsystems populate a handler registry before startup, and each inbound command is dispatched to the function registered for its exact topic.

```mermaid
flowchart LR
    INIT["Subsystem init"] -->|"topic + handler"| REG[("Handler registry")]
    START["Start MQTT after Wi-Fi"] --> SUB["Subscribe to registered topics"]
    REG --> SUB

    PUB["Command publisher"] --> BROKER[("MQTT broker")]
    BROKER -->|"topic + JSON payload"| MQTT["ESP-IDF MQTT v5 client"]
    MQTT --> CALLBACK["MQTT event callback"]
    CALLBACK --> LOOKUP{"Exact topic<br/>registered?"}
    REG --> LOOKUP
    LOOKUP -->|"No"| WARN["Log warning"]
    LOOKUP -->|"Yes"| ROUTE["Invoke registered handler"]
    ROUTE --> ACTION["LED, display, audio,<br/>OTA, or logger action"]
```

## Detailed architecture

```mermaid
flowchart TB
    subgraph BOOT["1. Boot-time registration"]
        direction LR
        APP["app_main()"] --> ID["identity_init()<br/>MAC address to device ID"]
        ID --> CTRL["led, display, audio,<br/>and OTA init"]
        CTRL --> LEDREG["Register cmd/rgb and<br/>cmd/notification"]
        CTRL --> DISPLAYREG["Register cmd/display"]
        CTRL --> AUDIOREG["Register cmd/audio"]
        CTRL --> OTAREG["Register cmd/ota"]
        LEDREG --> REGISTRY["s_cmd_dispatch<br/>exact topic to MqttCmdHandler"]
        DISPLAYREG --> REGISTRY
        AUDIOREG --> REGISTRY
        OTAREG --> REGISTRY

        APP --> WIFI["provisioning_start()<br/>wait for Wi-Fi IP"]
        WIFI --> DOWNLOADSTART["download::start()"]
        DOWNLOADSTART --> MQTTSTART["mqtt_io_start()<br/>register cmd/log; create and<br/>start MQTT v5 client"]
        MQTTSTART --> CALLBACK["mqtt5_event_handler()"]
    end

    subgraph TRANSPORT["2. Broker connection and command arrival"]
        direction LR
        PUBLISHER["Command publisher"] --> BROKER[("MQTT broker")]
        BROKER -->|"thelink/{ID}/cmd/…"| CALLBACK
        CALLBACK -->|"MQTT_EVENT_CONNECTED"| SUBSCRIBE["Subscribe to every map key<br/>QoS 1"]
    end

    subgraph ROUTING["3. Synchronous topic dispatch"]
        direction LR
        CALLBACK -->|"MQTT_EVENT_DATA"| PAYLOAD["Copy payload and append NUL"]
        PAYLOAD --> LOOKUP{"Exact topic found<br/>in s_cmd_dispatch?"}
        LOOKUP -->|"No"| UNKNOWN["Log warning only"]
        LOOKUP -->|"Yes"| INVOKE["it->second(payload)<br/>invoke registered handler"]
    end

    subgraph HANDLERS["4. Handler-specific parsing and actions"]
        direction LR
        INVOKE --> LEDH["LED handlers<br/>cJSON validation<br/>update RGB or notification state"]
        INVOKE --> DISPLAYH["Display handler<br/>cJSON validation<br/>enqueue download or set image"]
        INVOKE --> AUDIOH["Audio handler<br/>cJSON validation<br/>enqueue download or play file"]
        INVOKE --> OTAH["OTA handler<br/>cJSON validation<br/>publish started; enqueue firmware"]
        INVOKE --> LOGH["Logger handler<br/>cJSON validation<br/>get or set log level"]
    end

    subgraph EFFECTS["5. Downstream effects"]
        direction LR
        LEDH --> LEDTASK["LED task<br/>render RGB strip"]
        LEDH -->|"RGB state accepted"| EVTLED["Publish evt/led"]
        DISPLAYH --> DISPLAYTASK["Display task<br/>render SD-card image"]
        AUDIOH --> AUDIOTASK["Audio task<br/>play SD-card audio"]

        DISPLAYH -->|"URL command"| DOWNLOAD["FreeRTOS download queue<br/>and AsyncDownloader"]
        AUDIOH -->|"URL command"| DOWNLOAD
        OTAH -->|"firmware URL"| DOWNLOAD
        DOWNLOAD --> DISPLAYCB["Display completion callback"]
        DOWNLOAD --> AUDIOCB["Audio completion callback"]
        DOWNLOAD --> OTACB["OTA completion callback<br/>validate, flash, and reboot"]
        DISPLAYCB --> DISPLAYTASK
        AUDIOCB --> AUDIOTASK
        OTACB --> EVTOTA

        LOGH --> LOGGER["MQTT logger"]
        LOGGER --> EVTLOG["Publish evt/log"]
        OTAH --> EVTOTA["Publish evt/ota"]
    end

    EVTLED --> BROKER
    EVTLOG --> BROKER
    EVTOTA --> BROKER
```

## Registered routes

| Exact command topic | Handler | Main effect |
|---|---|---|
| `thelink/{ID}/cmd/rgb` | `led_ctrl::handle_rgb_command` | Validates and updates RGB state, optionally persists it, then publishes `evt/led`. |
| `thelink/{ID}/cmd/notification` | `led_ctrl::handle_notification_command` | Validates `message` and updates notification LED state; it does not publish an `evt/led` response. |
| `thelink/{ID}/cmd/display` | `display_ctrl::handle_command` | Validates `download` and `filename`, optionally queues a download, and updates display state. |
| `thelink/{ID}/cmd/audio` | `audio_ctrl::handle_command` | Validates `download`, `filename`, and optional `volume`, then queues or plays audio. |
| `thelink/{ID}/cmd/ota` | `ota_ctrl::handle_command` | Validates the firmware URL, publishes `evt/ota: started`, and queues `update.bin`. |
| `thelink/{ID}/cmd/log` | `mqtt_logger_handle_command` | Handles `get_level` and `set_level`; responses use `evt/log`. |

## Source map

- Device-specific topic construction: `main/identity.cpp:21-42`
- Controller registration before networking: `main/app_main.cpp:63-74`
- Command registry and registration API: `main/mqtt_io.cpp:18-23`, `main/mqtt_io.hpp:8-13`
- Broker-dependent startup: `main/provisioning.cpp:678-701`
- MQTT v5 client creation: `main/mqtt_io.cpp:116-128`
- Subscription creation from registry keys: `main/mqtt_io.cpp:40-49`
- Payload copy, exact lookup, and direct invocation: `main/mqtt_io.cpp:71-100`
- Display, audio, and firmware routing through the download queue: `main/download_mgr.cpp:45-58`, `main/download_mgr.cpp:128-150`

## Routing characteristics

- The topic lookup is exact; there is no wildcard or fallback handler.
- JSON parsing and field validation happen inside the selected handler, not in shared inbound middleware.
- The selected handler runs synchronously on the MQTT event task. Display, audio, and OTA URL commands defer network downloads to the download queue.
- There is no common command authentication, request ID, result envelope, or error response contract.
