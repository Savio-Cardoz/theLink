# 005 - MQTT client never starts after first-time provisioning (mqtt_task creation fails)

| Field | Value |
|---|---|
| Status | **Fixed** - awaiting on-device confirmation |
| Found | 2026-10-03 |
| Evidence | `/home/savio/run_3.txt` |
| Device log version | `0.4.1`, ESP-IDF v5.4.1, esp32s3 |
| Branch | `fixstuff` |
| Related | [`001-epd-154-heap-exhaustion.md`](./001-epd-154-heap-exhaustion.md), [`003-epd-spi-dma-no-mem.md`](./003-epd-spi-dma-no-mem.md), [`004-security2-srp-double-free-reboot.md`](./004-security2-srp-double-free-reboot.md) |

## Symptom

Provisioning now completes cleanly - the security2 handshake succeeds, Wi-Fi
associates and gets an IP address, SNTP syncs. The device then looks healthy
but never reaches the broker: there is no `MQTT_EVENT_CONNECTED`, and nothing
that the firmware publishes ever arrives.

From `run_3.txt`:

```
I (48950) app: Connected with IP Address:192.168.1.35
I (48950) app: Wi-Fi Up! Cleared binary image QR matrix widget.
I (48950) esp_netif_handlers: sta ip: 192.168.1.35, mask: 255.255.255.0, gw: 192.168.1.1
E (48950) mqtt_client: Error create mqtt task
I (48950) network_prov_mgr: STA Got IP
...
W (54830) BT_HCI: hci cmd send: disconnect: hdl 0x1, rsn:0x13
I (55850) network_prov_mgr: Provisioning stopped
I (55850) network_prov_scheme_ble: BTDM memory released
```

The same log also confirms [`004`](./004-security2-srp-double-free-reboot.md)
is fixed: `I (27060) app: Secured session established!` and no reboot.

## Root cause

`mqtt_client: Error create mqtt task` is emitted by
`esp_mqtt_client_start()` when `xTaskCreate()` returns anything other than
`pdTRUE`:

```c
/* components/mqtt/esp-mqtt/mqtt_client.c:1772 */
if (xTaskCreate(esp_mqtt_task, "mqtt_task", client->config->task_stack, client,
                client->config->task_prio, &client->task_handle) != pdTRUE) {
    ESP_LOGE(TAG, "Error create mqtt task");
```

So the task simply could not be allocated. Two things had to be true for that.

### 1. esp-mqtt asked for 6144 bytes of contiguous internal RAM

`main/mqtt_io.cpp` builds the config with `esp_mqtt_client_config_t mqtt5_cfg = {}`
and never sets `.task.stack_size`, so esp-mqtt falls back to its compiled
default:

```c
/* esp-mqtt/lib/include/mqtt_config.h:45-49 */
#define MQTT_TASK_STACK             (6*1024)
```

`CONFIG_MQTT_TASK_STACK_SIZE` cannot be used instead - it `depends on
MQTT_USE_CUSTOM_CONFIG`, and `CONFIG_MQTT_USE_CUSTOM_CONFIG` is not set. On top
of that, `esp_mqtt_client_init()` had *already* taken roughly 3 KB: the client
struct, config storage, a recursive mutex, an event group, and the default
1024-byte in/out message buffers.

### 2. The Bluetooth controller was still holding that memory

This is the part that only affects first-time provisioning. Inside
`wifi_prov_task` there are two paths that converge on the same
`xEventGroupWaitBits(... WIFI_CONNECTED_EVENT ...)` at `main/provisioning.cpp:688`:

| Boot path | `network_prov_mgr_deinit()` before the IP arrives? | MQTT starts |
|---|---|---|
| Already provisioned (`main/provisioning.cpp:674-685`) | **Yes**, at line 680 | succeeds |
| Fresh provisioning (`main/provisioning.cpp:653-673`) | **No** | **fails** |

The already-provisioned path never starts BLE, so it releases the manager
upfront and BTDM is long gone by the time MQTT starts. The fresh-provisioning
path starts the BLE scheme and then immediately waits for the IP, keeping the
whole Bluedroid + BT controller footprint resident.

Internal heap at that point was already thin:

```
I (3300) app: [HEAP] after provisioning_start: INTERNAL free=126419, largest_blk=32768
```

and BTDM takes a large slice of what is left. The 6144-byte request needs one
contiguous block, which is exactly what a fragmented internal heap stops
providing.

BTDM is only given back when provisioning ends. `esp_network_provisioning`
arms a **30 second** auto-stop timer on `IP_EVENT_STA_GOT_IP`
(`CONFIG_NETWORK_PROV_AUTOSTOP_TIMEOUT=30`, `manager.c:1782`), and in this
capture the provisioning client hung up first at 54830, so:

```
MQTT start attempt at 48950  ->  fails
BTDM released at       55850  ->  6.9 s too late
```

### 3. Nothing checked the result, and nothing retried

`mqtt_io_start()` discarded both return codes and the call was made once,
straight-line, with no retry and no error path. Worse, `esp_mqtt_client_init()`
*had* succeeded, so `app::set_mqtt()` stored a **task-less** client handle.
`app::mqtt_publish()` only null-checks the pointer:

```cpp
/* main/app_common.cpp:31-39 */
if (s_mqtt == nullptr) return false;
int msg_id = esp_mqtt_client_publish(s_mqtt, topic, payload, 0, qos, retain);
return msg_id >= 0;
```

so status/LED/OTA publishes would enqueue into a client with no task and
**report success while delivering nothing**. And because `app::fire_on_connect()`
only runs from `MQTT_EVENT_CONNECTED`, the notification LED never handed back to
MQTT control either.

## Fix

### Retry the start until BTDM is released

`mqtt_io_start()` now returns `esp_err_t` (`main/mqtt_io.hpp`), and
`wifi_prov_task` retries it 1 s apart, 60 times
(`MQTT_START_MAX_ATTEMPTS`, `main/provisioning.cpp:129-134`). That covers both
ways provisioning ends - the client hanging up (a few seconds) and the 30 s
auto-stop timer.

Provisioning teardown is deliberately **not** forced. `network_prov_manager`
offers `network_prov_mgr_stop_provisioning()` and
`network_prov_mgr_disable_auto_stop()` for this, but the component docs note the
auto-stop delay exists so the client can still query network state after
handing over credentials. Ending BLE early risks truncating that exchange, so the
retry waits for the memory instead.

### Report failure, destroy the partial client, never leave a dead handle

`mqtt_io_start()` now checks `esp_mqtt_client_init()` and
`esp_mqtt_client_start()`, and on failure clears `app::set_mqtt(NULL)` before
`esp_mqtt_client_destroy()`. That closes the false-success path and stops the
~3 KB of client state leaking on every attempt. If all attempts are exhausted
the device logs one error and keeps running without cloud connectivity rather
than looping forever.

`mqtt_register_cmd()` is safe to call again on each attempt - it is a map write
(`main/mqtt_io.cpp:20-23`) - and subscriptions are derived per client inside
`MQTT_EVENT_CONNECTED`, so a rebuilt client cannot double-subscribe.

### Return headroom to internal RAM

`CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM` reduced from the default 32 to 16 in
`sdkconfig.defaults`. Wi-Fi RX buffers were the single largest internal-DMA
consumer, and returning roughly 25 KB gives the Bluetooth controller and the
esp-mqtt task real margin instead of relying on a lucky fragmentation pattern.
This is the item previously deferred in
[`003`](./003-epd-spi-dma-no-mem.md#follow-ups-not-done-here); it trades some
Wi-Fi RX throughput.

## Follow-ups not done here

1. **`app::mqtt_publish()` can still report false success.** If the broker is
   unreachable, publishes queue into the outbox and return a valid `msg_id`
   until the outbox fills. A "connected" flag checked in `mqtt_publish()` would
   make this honest.
2. **The failure is only visible by log.** Nothing surfaces "MQTT is down" on
   the device; `status_ctrl` could publish/report it once
   `MQTT_EVENT_CONNECTED` has been seen at least once.
3. **`esp_mqtt_client_start()` is still the only heap gate.** If the internal
   heap is ever too fragmented even after BTDM release, the retry will simply
   run out of attempts. Worth re-measuring `largest_blk` against the 6144-byte
   request in the `mqtt_io_start failed, retrying` log lines added here.