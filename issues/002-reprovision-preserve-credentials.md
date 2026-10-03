# 002 - Re-provisioning should not obliterate existing Wi-Fi credentials

| Field | Value |
|---|---|
| Status | **Open** - design discussion only, not implemented |
| Raised | 2026-10-02 |
| Branch | `fixstuff` (design captured alongside the 001 fix) |
| Related | [`001-epd-154-heap-exhaustion.md`](./001-epd-154-heap-exhaustion.md), [`003-epd-spi-dma-no-mem.md`](./003-epd-spi-dma-no-mem.md) |

## Problem

Holding the provisioning button at boot is a hard factory reset: it erases the
entire NVS default partition, destroying stored Wi-Fi credentials. Two paths
cause this:

1. `check_reset_button_at_boot()` (`main/app_main.cpp:41`, GPIO3, active-low)
   sets `dynamic_factory_reset` (`main/app_main.cpp:86`), and the handler calls
   `nvs_flash_erase()` at `main/app_main.cpp:94` with the comment
   *"This completely wipes the default NVS partition where credentials live."*
2. `main/provisioning.cpp:529` also calls
   `network_prov_mgr_reset_wifi_provisioning()` under
   `CONFIG_EXAMPLE_RESET_PROVISIONED`, which is `esp_wifi_restore()` internally.

## Why re-provisioning never re-triggers

The binding constraint is the provisioned-state gate. `provisioning.cpp:536`
gates the provisioning service behind `if (!provisioned)`, where
`provisioned` comes from `network_prov_mgr_is_wifi_provisioned()`
(`provisioning.cpp:532`). That function reads the live STA config and returns
true whenever an SSID is set - it is not a separate provisioning-state flag.

So with credentials present, `provisioned == true`, the service never starts,
and the only way to re-enter provisioning is to destroy those credentials
first. The two behaviours are circularly coupled. Any fix must break that
coupling.

## Design options

### Option A - Custom reprovision flag

Remove `nvs_flash_erase()` from `main/app_main.cpp:94`. On button press, write
a `reprovision_requested` flag into a *non-erased* NVS namespace. Gate
provisioning on `provisioned || reprovision_requested`, allowing new
credentials to overwrite old ones in the default namespace while keeping the
old credentials available for fallback.

Trade-off: we own the state machine, including deciding when to clear the flag.

### Option B - `network_prov_mgr_reset_wifi_sm_state_for_reprovision()`

The upstream manager already provides a non-destructive reset
(`network_prov_mgr_reset_wifi_sm_state_for_reprovision()`,
`managed_components/espressif__network_provisioning/src/manager.c:2385`).
It explicitly keeps storage in RAM (`esp_wifi_set_storage(WIFI_STORAGE_RAM)`
at `:2404`), clears only the in-RAM STA config, disconnects, restores
`WIFI_STORAGE_FLASH`, resets `prov_ctx->prov_state`, and fires
`NETWORK_PROV_START`. NVS credentials are never touched.

Two real constraints:

- It calls `execute_event_cb(NETWORK_PROV_START, ...)`, which conflicts with the
  existing `NETWORK_PROV_END` handling that tears the manager down
  (`main/provisioning.cpp:362`). Wiring this into the current event flow needs
  care around manager lifetime.
- It does not remove the `provisioned` gate; the button state must still be
  tracked separately to get past `provisioning.cpp:536`.

### Option C - Runtime button instead of boot-only

Detect a long press on the factory-reset button after boot, so the button
changes provisioning state directly instead of depending on the
`check_reset_button_at_boot()` flag. Removes the timing sensitivity, but is a
larger change to the input path.

## Credential storage caveat

Worth resolving before any of the options is written: the ESP-IDF Wi-Fi driver
keeps a single STA config slot in NVS. `esp_wifi_set_config(...,
WIFI_STORAGE_FLASH)` overwrites that slot on every call, and the provisioning
manager writes the freshly received credentials into it immediately.

Consequence: once new credentials land, the old ones are gone - there is no
second slot to fall back to. A genuine "keep the old credentials if no new
ones arrive" guarantee therefore likely needs an explicit shadow copy in our
own NVS namespace, saved before provisioning starts and restored on timeout or
explicit abort. Whether that is acceptable needs a decision before coding.

## Related hazard

`main/provisioning.cpp:351` calls
`network_prov_mgr_reset_wifi_sm_state_on_failure()` when
`CONFIG_EXAMPLE_RESET_PROV_MGR_ON_FAILURE` is set (default `y`,
`main/Kconfig.projbuild:109`, `EXAMPLE_PROV_MGR_CONNECTION_CNT` default 5).
That path also drops credentials after retries, so a user with working Wi-Fi
who mistypes a password during re-provisioning ends up with no credentials at
all - the same data-loss class as this issue, reached by a different route.

## Open questions

- Should re-provisioning attempt the new SSID, then fall back to the stored one
  on failure, or leave the existing connection untouched until the new one is
  proven?
- Is a provisioning timeout needed, and how long?
- Should the shadow copy of old credentials survive across the reboot, or only
  for the session?
- Does the user expect the button to be usable after boot (runtime long-press),
  or only at power-up as today?