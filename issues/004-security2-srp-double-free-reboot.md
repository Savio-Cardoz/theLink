# 004 - Device reboots when a BLE provisioning client connects (security2 SRP double free)

| Field | Value |
|---|---|
| Status | **Fixed** - awaiting on-device confirmation |
| Found | 2026-10-03 |
| Evidence | `/home/savio/run_2.txt` |
| Device log version | `0.4.1`, ESP-IDF v5.4.1, esp32s3 |
| Branch | `fixstuff` |
| Related | [`001-epd-154-heap-exhaustion.md`](./001-epd-154-heap-exhaustion.md), [`003-epd-spi-dma-no-mem.md`](./003-epd-spi-dma-no-mem.md) |

## Symptom

Provisioning starts, the QR code renders and scans, and the client connects.
The moment the security2 handshake runs, the device asserts and reboots. It
repeats on every attempt.

From `run_2.txt`:

```
I (33377) BLE transport: Connected!
I (35017) security2: Using salt and verifier to generate public key...
mbedtls_mpi_mod_mpi() failed, returned fffffff0
E (35267) security2: Failed to generate device session key!
E (35277) security2: Session setup error -1
E (35277) protocomm_ble: Invalid content received, killing connection
W (35287) BT_HCI: hci cmd send: disconnect: hdl 0x1, rsn:0x13

assert failed: heap_caps_free heap_caps_base.c:74 (heap != NULL && "free() target pointer is outside heap areas")
...
rst:0xc (RTC_SW_CPU_RST), boot:0x8 (0x40018000)
```

## Root cause

Two separate defects stack up. The first only aborts the handshake; the second
turns that abort into a reboot.

### 1. Trigger: mbedTLS could not allocate, because it was locked out of PSRAM

`mbedtls_mpi_mod_mpi() failed, returned fffffff0` is not a crypto error.
`0xfffffff0` is `-0x0010`, which is `MBEDTLS_ERR_MPI_ALLOC_FAILED` in
`mbedtls/bignum.h`. The bignum code simply ran out of heap.

The cause is a memory-cap restriction. `CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC=y`
made every mbedTLS allocation use:

```c
heap_caps_calloc(n, size, MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
```

(`components/mbedtls/port/esp_mem.c`). `MALLOC_CAP_INTERNAL` excludes PSRAM, so
none of the 8 MB of PSRAM was available to mbedTLS. Meanwhile the internal heap
is what the BLE and Wi-Fi stacks, LVGL and the E-Paper driver all contend for.
By the time the phone connects, the log shows the internal heap down to
`largest_blk=32768`:

```
I (2027) app: [HEAP] after display_ctrl::start: INTERNAL free=132199, largest_blk=38912
I (2047) app: [HEAP] after provisioning_start: INTERNAL free=126367, largest_blk=32768
```

So the SRP6a temporaries for a 3072-bit group could not be allocated, and
session setup returned `ESP_FAIL`.

### 2. The crash: `protocomm` double-frees the SRP handle on every setup failure

This is the actual reboot, and it is an upstream ESP-IDF defect in
`components/protocomm/src/security/security2.c`. Five error paths free the
session's SRP handle and return without clearing the pointer:

```c
if (esp_srp_get_session_key(cur_session->srp_hd, ..., &cur_session->session_key,
                            &cur_session->session_key_len) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to generate device session key!");
    esp_srp_free(cur_session->srp_hd);   // freed...
    return ESP_FAIL;                      // ...but srp_hd is left dangling
}
```

The same pattern repeats at the salt/verifier, device-pubkey, response-allocation
and username-allocation failure paths. Because `cur_session->srp_hd` is still
non-NULL and now dangling, the subsequent BLE disconnect frees it **again**:

```
sec2_close_session (security2.c:400)  ->  if (cur_session->srp_hd) esp_srp_free(...)
```

The second `esp_srp_free()` reads `hd->ctx` out of memory that has already been
freed and handed back to the Bluetooth stack, so the pointer is garbage. It is
passed to `mbedtls_mpi_free()`, which tries to release the limb buffer at that
address and trips the allocator's own consistency check:

```
assert failed: heap_caps_free heap_caps_base.c:74 (heap != NULL && "free() target pointer is outside heap areas")
```

### Backtrace

Decoded against the exact crashing image (ELF SHA-256 prefix `e93687162`,
preserved at `/tmp/opencode/theLink_crash_e93687162.elf`):

```
heap_caps_free            heap/heap_caps_base.c:74      <- assert
esp_mbedtls_mem_free      mbedtls/port/esp_mem.c:38
mbedtls_free              mbedtls/library/platform.c:54
mbedtls_zeroize_and_free  mbedtls/library/platform_util.c:145
mbedtls_mpi_free          mbedtls/library/bignum.c:198
esp_mpi_free              protocomm/src/crypto/srp6a/esp_srp_mpi.c:54
esp_mpi_ctx_free          protocomm/src/crypto/srp6a/esp_srp_mpi.c:67
esp_srp_free              protocomm/src/crypto/srp6a/esp_srp.c:141
sec2_close_session        protocomm/src/security/security2.c:400
transport_simple_ble_disconnect  protocomm/src/transports/protocomm_ble.c:347
gatts_profile_event_handler      protocomm/src/simple_ble/simple_ble.c:168
btc_thread_handler / vPortTaskWrapper
```

## Fix

Switch mbedTLS to allocate from PSRAM instead of the internal heap:

```
CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC=y
```

added to `sdkconfig.defaults`, so both the Dev and Prod profiles pick it up.
`esp_mbedtls_mem_calloc()` then uses `MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT` and
the SRP6a temporaries come from the 8 MB of PSRAM that was sitting idle. The
IDF `Kconfig` help recommends exactly this mode for devices where internal
memory is tight, and notes that on the ESP32-S3 it is also safe from a security
 standpoint when flash encryption is used.

This removes the allocation failure, so session setup now succeeds and the
double-free path in defect 2 is never entered.

## Follow-ups not done here

1. **The double-free is still latent.** This fix stops the trigger, not the
   bug. Any other reason for security2 setup to fail - a malformed client
   request, an unexpected username - walks the same
   `esp_srp_free()` / `esp_srp_free()` path and reboots the device the same
   way. The real repair is to null `cur_session->srp_hd` after freeing it on
   all five paths. That lives in `protocomm`, an IDF component outside this
   repository, so fixing it means carrying a local patch or vendored override.
   Worth tracking before this reaches production.
2. **`esp_mpi_a_mul_b_mod_c()` leaks on its error path**
   (`protocomm/src/crypto/srp6a/esp_srp_mpi.c:105`). It builds `t` with
   `mbedtls_mpi_mul_mpi()` and returns without `mbedtls_mpi_free(&t)` when the
   following `mbedtls_mpi_mod_mpi()` fails. `esp_mpi_a_add_b_mod_c()` has the
   same shape. Harmless while setup succeeds, but it leaks on every failure.