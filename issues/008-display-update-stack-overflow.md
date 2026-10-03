# 008 - Stack overflow in `display_update` when pushing an image to the e-paper canvas

| Field | Value |
|---|---|
| Status | **Fixed** - confirmed on device |
| Found | 2026-10-03 |
| Evidence | Crash: `/home/savio/run4.txt` - fix confirmed: `/home/savio/run_6.txt` |
| Device log version | `0.4.1`, ESP-IDF v5.4.1-dirty, esp32s3 |
| Baseline ELF | `ba80da3bbf9d9ac9719526d13e40dc979c6f192dc43605656637cf1eb9bd48f` (compile time `Oct  3 2026 12:25:53`) |
| Fixed ELF | `ab15e5c31...` (compile time `Oct  3 2026 15:18:41`) |
| Branch | `fixstuff` |
| Related | [`001-epd-154-heap-exhaustion.md`](./001-epd-154-heap-exhaustion.md), [`003-epd-spi-dma-no-mem.md`](./003-epd-spi-dma-no-mem.md), [`004-security2-srp-double-free-reboot.md`](./004-security2-srp-double-free-reboot.md), [`005-mqtt-task-start-heap.md`](./005-mqtt-task-start-heap.md) |

This issue is **independent of the security2 work**. The crashing firmware is
the pre-security2 baseline ELF, and the faulting task (`display_update`) is not
touched by anything in `components/protocomm`.

## Symptom

Pushing a second and third image into the e-paper canvas in the same boot
session aborts with a FreeRTOS stack overflow in `display_update`:

```
I (57011) app: Unpacking 41KB I8 Asset from SD Card: /sdcard/dog.bin
I (57111) app: Unpacking complete. Pushing canvas to widget container...
I (57291) FLUSH: Executing Global Full Refresh -> Black: 15066, White: 24934
I (68271) app: Display command received
I (68271) app: Display download: http://80.225.207.106/esp32_images/us.bin -> us.bin
I (68301) app: File already available at: /sdcard/us.bin
I (68301) app: Updating display state with new data path: /sdcard/us.bin
I (68321) app: Notifying display task of new data path: /sdcard/us.bin
I (68321) app: Unpacking 41KB I8 Asset from SD Card: /sdcard/us.bin
I (68381) app: Unpacking complete. Pushing canvas to widget container...

***ERROR*** A stack overflow in task display_update has been detected.

Backtrace: 0x403760a1:0x3fcde580 0x40384951:0x3fcde5a0 0x4038586e:0x3fcde5c0
           0x403875e3:0x3fcde640 0x40385934:0x3fcde660 0x4038592a:0x3fcab4a4 |<-CORRUPTED
```

The abort happens between the "Unpacking complete" log and the flush. Note that
`dog.bin` rendered normally 11 seconds earlier on the identical code path, and
that heap was byte-for-byte identical for both commands:

```
I (57011) app: [HEAP] handle_display_command: total_free=8227844 | INTERNAL free=52471, largest_blk=25600   <- dog.bin, OK
I (68271) app: [HEAP] handle_display_command: total_free=8227844 | INTERNAL free=52471, largest_blk=25600   <- us.bin, overflow
```

After the device rebooted, the *same* `/sdcard/us.bin` pushed successfully at
`t=2107` and four further images pushed cleanly. The failure is intermittent
and not tied to any particular image.

## Root cause

The task stack was too small for the work the task does, with no margin left
for interrupt frames.

### 1. A 1 KiB buffer sat on the stack

`display_update_task` declared the palette as a local inside the unpack path:

```cpp
/* main/display_ctrl.cpp:90 (before fix) */
uint8_t palette[1024];
fread(palette, 1, 1024, f);
```

Disassembling the object confirms how much of the frame that consumed:

```
$ xtensa-esp32s3-elf-objdump -d build/esp-idf/main/CMakeFiles/__idf_main.dir/display_ctrl.cpp.obj
00000000 <_ZL19display_update_taskPv>:
   0:   088136    entry   a1, 0x440        <- 1088-byte frame
```

1088 bytes of static locals against a 4096-byte stack, i.e. the palette alone
consumed a quarter of the budget before a single call was made. The remaining
~3 KB had to cover `fopen`/`fseek`/`fread` (newlib + FatFS), `std::string`
copy/assign under a `std::mutex`, the `ESP_LOGI` varargs formatting, and the
LVGL invalidate chain. The individual LVGL frames are modest
(`lv_image_set_src` 0x80, `lv_image_decoder_get_info` 0x112, `lv_refr_join_area`
0x48), so this is cumulative exhaustion rather than one pathological frame.

### 2. The 200x200 flush is not the culprit

Worth ruling out explicitly, because it is the obvious suspect: the flush does
**not** run on this stack. `ui_lock`/`ui_unlock` bracket only the LVGL object
mutation, and the actual E-Paper transfer is driven later by `lv_timer_handler`
on the separate 8192-byte LVGL task (`main/app_main.cpp:174`). The 100-500 ms
gap between "Pushing canvas" (`t=68381`) and `FLUSH:` is that hand-off. Growing
the flush path's stack would not have fixed anything.

### 3. Interrupts run on the task's stack, which is what makes it intermittent

This is the part that explains why a marginally-sized stack fails sometimes and
not otherwise. ESP-IDF services interrupts on the interrupted task's stack, so
this task's 4 KB had to absorb nested Wi-Fi, SPI and SDMMC frames while doing
file I/O. At the crash timestamp the log shows live Wi-Fi association activity
(`wifi:connected with Cardoz` at `t=4557`, state transitions right through the
window), so the interrupt load was real.

That makes the fault a race against interrupt-frame arrival rather than a
property of any image. Both the heap reading and the code path were identical
between the succeeding and failing push, which is exactly the signature of an
ISR-timing-dependent overflow. Heap exhaustion is ruled out independently:
`free=52471`, `largest_blk=25600` at the fault.

### 4. Why the backtrace was unusable

`CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY=y` (`build/sdkconfig:1741`) means
detection happens at a context switch, not at the fault site. The reported
frames are therefore the dispatcher/panic path, not the overflowing call chain:

- consecutive stack pointers differ by only `0x20`, consistent with the switch path;
- the final frame is `<-CORRUPTED`.

This is also why obtaining the matching `ba80da3bb` ELF would **not** have
recovered the real frames. The `main` symbols resolved against the current ELF
land in `vApplicationStackOverflowHook` / `vTaskSwitchContext` /
`_frxt_dispatch`, confirming the diagnosis. Correct action was to measure peak
usage rather than chase symbols.

## Fix

Two changes in `main/display_ctrl.cpp`, applied together.

### Move the palette into SPIRAM

```cpp
// The 1,024-byte palette is kept in SPIRAM rather than as a local: this task
// runs a tight stack and the local cost is significant. See issues/008.
static uint8_t *palette = (uint8_t *)heap_caps_malloc(1024, MALLOC_CAP_SPIRAM);
assert(palette != NULL);
```

Placed next to the existing 80 KB PSRAM canvas, and initialised once before the
notify loop alongside it. The 1024 bytes now come from PSRAM instead of the
stack, so the frame drops from 1088 bytes to roughly 64. The `static` local is
still a pointer, so the allocation happens exactly once, on first pass through
that code, and the lifetime matches the other `static` buffers. The `assert`
mirrors the adjacent canvas allocation so a failed PSRAM init fails loudly at
task start rather than corrupting memory later.

### Raise the task stack to 8192 bytes

```cpp
// main/display_ctrl.cpp:start()
xTaskCreate(display_update_task, "display_update", 8192, NULL, 4, &s_display_task_handle);
```

8192 is not an arbitrary figure. ESP-IDF's `xTaskCreate` takes **bytes** (not
words) - the repo already documents this at `main/data_downloader.cpp:238-240`,
where the same measurement convention is why the storage and HTTP tasks use
8192. This makes `display_update` consistent with the three other
image/audio-heavy tasks:

| Task | Stack | Location |
|---|---|---|
| `LVGL` | 8192 | `main/app_main.cpp:174` |
| `audio_play` | 8192 | `main/audio_ctrl.cpp:198` |
| `StorageTask` | 8192 | `main/data_downloader.cpp:240` |
| `HttpTask` | 8192 | `main/data_downloader.cpp:249` |
| **`display_update`** | **4096 -> 8192** | `main/display_ctrl.cpp:278` |

Both changes are needed. Moving the palette alone frees stack but does nothing
for ISR nesting; raising the stack alone leaves a 1 KiB buffer on a task whose
problem is marginal headroom.

### Instrument the high-water mark

```cpp
ESP_LOGI(TAG, "Display push complete: %s. Stack HWM=%" PRIu32,
         file_path.c_str(), (uint32_t)uxTaskGetStackHighWaterMark(NULL));
```

Logged after each successful push, i.e. after the deepest path has run.
`uxTaskGetStackHighWaterMark` reports the *lowest* free level ever reached, which
is precisely the quantity the canary compares against, so this number predicts
the fault rather than merely describing it. The pattern is copied from the
existing logging at `main/data_downloader.cpp:59-60` and `:190-191`.

This matters because a stack bump can otherwise convert a loud crash into a
silent one: had 4096 overflowed and the stack simply been raised to 8192, the
same defect could resurface much later with a corrupted backtrace and no
warning. With the log line present, an approaching overflow is visible in the
serial output as a shrinking HWM.

## Cost of the fix

Task stacks are allocated from **internal** RAM, not PSRAM, so the 4 KB is
permanent internal-heap pressure. Internal heap is already the tight resource
in this firmware:

- tightest observed internal free in the capture is **49,735 bytes** with
  `largest_blk=24,576` (`run4.txt:501`), at the moment an HTTP download starts;
- `CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=16384` and
  `CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=32768` mean allocations below 32 KB are
  forced to internal and cannot spill to PSRAM.

So 4 KB is roughly 8% of worst-case internal free. `display_update` is created
at `main/app_main.cpp:176`, before `provisioning_start`, so the charge lands
early: expect the post-`display_ctrl::start` reading to fall from
`INTERNAL free=131,887` (`run4.txt:115`) to about 127,900, with every later
internal-heap reading shifted down by the same 4 KB. This is the direct
consequence of the fix and is accepted deliberately, in exchange for removing
a crash; it is recorded here so a future heap regression can be attributed
correctly.

Measured on the fixed build, the prediction was accurate to 16 bytes:

| | `after display_ctrl::start` | stack |
|---|---|---|
| baseline (`run4.txt:115`) | `INTERNAL free=131,887` | 4096 |
| fixed (`run_6.txt:256`) | `INTERNAL free=127,823` | 8192 |
| delta | **4,064 bytes (3.97 KB)** | |

## Verification

**Confirmed** in `/home/savio/run_6.txt` on fixed ELF `ab15e5c31...` (compile
time `Oct  3 2026 15:18:41`, matching the local build). All checks passed.

| # | Check | Result |
|---|---|---|
| 1 | No `stack overflow in task display_update` across the session | **pass** - zero occurrences in 355 lines |
| 2 | `Stack HWM=` present on every push | **pass** - 9 pushes, 9 readings |
| 3 | HWM stable, not falling | **pass** - `5208` on all 8 warm pushes |
| 4 | `Unpacking complete` followed by `FLUSH:` | **pass** - 9/9, Black/White counts varied per image |
| 5 | `after display_ctrl::start` heap drop ~4 KB | **pass** - 4,064 bytes (above) |
| 6 | Images render correctly | **pass** (operator-confirmed) |

Nine images pushed in one session, including three downloaded fresh rather than
served from SD cache (`worldtravel.bin`, `cat.bin`, `rose.bin`), plus a reboot
and a further push. This is the scenario that used to fail on the second/third
push. No E- or W-level log lines appear anywhere in the capture.

### The measurement closes the diagnosis

`uxTaskGetStackHighWaterMark` reports the *minimum free* level, so peak task
usage is `8192 - 5208 = 2984` bytes. The pre-fix frame was 1088 bytes against
the current 80, so implied peak usage before the fix was roughly
`2984 + (1088 - 80) = 3992` bytes against a 4096-byte stack:

| | stack | peak usage | headroom |
|---|---|---|---|
| before | 4096 | ~3992 | **~104 bytes** |
| after | 8192 | 2984 | **5208 bytes** |

That ~104-byte margin is the whole bug. It explains three things at once:

- why `dog.bin` and `us.bin` both fit *just barely* on identical code paths,
- why the fault was intermittent, since ISR nesting only had ~104 bytes to
  work with, and
- why it took a Wi-Fi-active window to trip rather than failing every time.

It also confirms the ISR reasoning in the root-cause section was the right
explanation: the task path alone did not overflow. It ran out of room when
interrupts were added to it. Note this means the stack bump was the load-bearing
change - moving the palette alone would have bought back only ~1008 of those
104 bytes of headroom, leaving the margin at roughly 1112 bytes rather than
comfortable.

The boot-session reading differs (`HWM=6120` on the first post-reboot push,
`run_6.txt:295`) because less nesting had occurred at that point - Wi-Fi was
still associating and the flush had not run yet. Steady state is `5208`, and it
does not degrade as pushes accumulate, so there is no leak in the push path.

Unrelated but reassuring: `StorageTask`/`HttpTask` HWM (`3180`/`2928`) are also
steady, and `Storage Task: launch returned pdPASS` throughout, so the 4 KB
taken by `display_update` did not starve the download path.

## Follow-ups not done here

1. **Internal heap headroom is the next real constraint.** `largest_blk` falls
   from 106,496 to 36,864 across `display_ctrl::start` (`run4.txt:115`) - a
   single allocation larger than the entire stack increase above. That is not
   part of this fix, but it is a bigger consumer than anything discussed here
   and deserves its own look before more permanent internal allocations are
   added.
2. **A 4096-byte overflow could now be an 8192-byte overflow.** The HWM log is
   the mitigation, but nothing alerts on it. A threshold warning (or a
   `status_ctrl` publish when HWM drops below some margin) would turn a future
   regression into an event rather than a log line somebody has to notice.
3. **ISR nesting on this task is unbounded regardless of stack size.** 8192
   gives real headroom but does not bound interrupt depth. The measurement
   above shows the push path peaks at 2984 bytes, so the remaining 5208 is
   genuinely ISR/interrupt-frames allowance and is what keeps this safe. If a
   future change pushes HWM much lower, the durable fix is to move the file
   I/O off this task (or onto the other core) rather than to keep growing the
   stack. Worth knowing which factor dominates: the current figures cannot
   separate ISR cost from the task's own deepest call chain, because the HWM
   is only sampled after the push returns.
4. **`palette` is not validated after `fread`.** A short read leaves stale
   bytes from the previous image in the buffer and silently produces a wrong
   palette. Return values of both `fread` calls are ignored today. Unrelated to
   the crash, but in the same three lines of code.