#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"

#include "cJSON.h"

#include <sys/time.h>
#include <time.h>

#include "i2c_bsp.h"
#include "pcf85063_bsp.h"
#include "user_config.h"

#include "app_common.hpp"
#include "config_store.hpp"
#include "identity.hpp"
#include "mqtt_io.hpp"
#include "status_ctrl.hpp"

#include "time_ctrl.hpp"

static const char *TAG = "TIME";

// pool.ntp.org resolves to a pool of servers and is the pool NTP itself
// recommends, so it avoids hard-coding a name that a given network blocks.
#define SNTP_SERVER "pool.ntp.org"

// How long to wait for the first correction after an address is acquired. lwIP's
// own schedule is the constraint, not this number: a random startup delay of up to
// 5 s, then a 15 s receive timeout per attempt, with the retry backoff doubling
// from 15 s. A single 30 s wait expired between attempt 1 and attempt 2, so a
// healthy server produced a false timeout on every boot. 120 s spans the first few
// attempts, and the wait only gates this module's own logging: lwIP keeps retrying
// in the background either way, and a later correction arrives as its own event.
#define SNTP_FIRST_SYNC_TIMEOUT_MS 120000

// A cell that has only ever held the power-on default reads back 1 January 2000.
// The PCF85063TP has no century bit, so this floor is the only way to tell a
// stale-but-populated calendar from a real one.
#define RTC_MIN_PLAUSIBLE_YEAR 2024

#define TIME_CTRL_EVENT_GOT_IP BIT0
#define TIME_CTRL_EVENT_SYNCED BIT1

namespace
{

    // How the current time was established. Reported verbatim in evt/status so a
    // clock corrected by the network is never mistaken for one merely restored
    // from the backup cell.
    enum class TimeSource
    {
        NONE, // no trustworthy time yet
        RTC,  // seeded from the battery-backed RTC
        SNTP, // corrected against an NTP server
    };

    const char *time_source_to_string(TimeSource source)
    {
        switch (source)
        {
        case TimeSource::RTC:
            return "rtc";
        case TimeSource::SNTP:
            return "sntp";
        default:
            return "none";
        }
    }

    // The last established time, plus everything needed to explain it. Guarded
    // because the SNTP callback writes it from the TCP/IP task while MQTT
    // commands and status queries read it.
    struct time_state_t
    {
        std::mutex mutex;
        TimeSource source = TimeSource::NONE;
        uint64_t established_ms = 0; // esp_timer stamp of the last sync or seed
        bool rtc_present = false;
        // The part holds a calendar worth reading: set at boot when it survives a
        // restart with OS clear, and set again on every write from SNTP. It is not
        // "the time is currently good" and it does not survive a power cycle: with
        // no backup source fitted the part is on the 3v3 rail, so an unplug leaves
        // it at the power-on default with OS set.
        bool rtc_valid = false;
        std::string tz; // POSIX TZ string, empty when undeclared
    };

    time_state_t g_state;

    EventGroupHandle_t s_time_events;

    // Days since 1970-01-01 for a proleptic Gregorian date, after Howard
    // Hinnant's `days_from_civil`. The C library offers no way to turn a UTC
    // calendar back into a time_t without dragging the local timezone in, and
    // dragging the local timezone in is exactly what must not happen here.
    int64_t days_from_civil(int y, int m, int d)
    {
        y -= m <= 2;
        const int64_t era = (y >= 0 ? y : y - 399) / 400;
        const int64_t yoe = y - era * 400;                                  // [0, 399]
        const int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1; // [0, 365]
        const int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;          // [0, 146096]
        return era * 146097 + doe - 719468;
    }

    // The UTC counterpart of mktime, which is absent from newlib. Used to seed
    // the system clock from the RTC, whose registers hold UTC by definition.
    time_t utc_timegm(const struct tm *t)
    {
        if (t == nullptr)
        {
            return (time_t)-1;
        }
        const int64_t days = days_from_civil(t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
        return (time_t)(days * 86400 + t->tm_hour * 3600 + t->tm_min * 60 + t->tm_sec);
    }

    // The UTC offset newlib is actually applying, in seconds, measured rather
    // than assumed. tm_gmtoff would be the obvious way to read this but it is
    // compiled out unless __TM_GMTOFF is defined, and this build does not define
    // it, so the offset is recovered by differencing the two broken-down times
    // for a fixed instant. That doubles as the check that a freshly applied TZ
    // really took effect, which is worth having given newlib's habit of keeping
    // a stale offset when TZ is set a second time.
    int32_t measure_utc_offset(time_t when)
    {
        struct tm local = {};
        struct tm utc = {};
        if (localtime_r(&when, &local) == nullptr || gmtime_r(&when, &utc) == nullptr)
        {
            return 0;
        }

        const int64_t local_days = days_from_civil(local.tm_year + 1900, local.tm_mon + 1, local.tm_mday);
        const int64_t utc_days = days_from_civil(utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday);
        return (int32_t)((local_days - utc_days) * 86400 +
                         (local.tm_hour - utc.tm_hour) * 3600 +
                         (local.tm_min - utc.tm_min) * 60 +
                         (local.tm_sec - utc.tm_sec));
    }

    void format_offset(char *out, size_t len, int32_t offset_seconds)
    {
        const int32_t abs_seconds = offset_seconds < 0 ? -offset_seconds : offset_seconds;
        // Casts because int32_t is long on Xtensa, which %d will not accept.
        snprintf(out, len, "%c%02d:%02d", offset_seconds < 0 ? '-' : '+', (int)(abs_seconds / 3600),
                 (int)((abs_seconds % 3600) / 60));
    }

    // "2026-10-01T06:12:33Z". strftime's %z is avoided below and here because a
    // bare "%Y-%m-%dT%H:%M:%S" plus a literal suffix behaves the same on every
    // libc, including this one.
    void format_utc(char *out, size_t len, time_t when)
    {
        struct tm tm_utc = {};
        if (gmtime_r(&when, &tm_utc) == nullptr)
        {
            snprintf(out, len, "null");
            return;
        }
        snprintf(out, len, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm_utc.tm_year + 1900, tm_utc.tm_mon + 1,
                 tm_utc.tm_mday, tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
    }

    // "2026-10-01T11:42:33+05:30", with the offset written out rather than left
    // to %z, for the same portability reason as above.
    void format_local(char *out, size_t len, time_t when)
    {
        struct tm tm_local = {};
        if (localtime_r(&when, &tm_local) == nullptr)
        {
            snprintf(out, len, "null");
            return;
        }

        char offset[8] = {0};
        format_offset(offset, sizeof(offset), measure_utc_offset(when));
        snprintf(out, len, "%04d-%02d-%02dT%02d:%02d:%02d%s", tm_local.tm_year + 1900, tm_local.tm_mon + 1,
                 tm_local.tm_mday, tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec, offset);
    }

    // Apply a POSIX timezone string and confirm it landed.
    //
    // The C library has no timezone database, so "Asia/Kolkata" resolves to
    // nothing and the offset silently stays at zero; only the POSIX form works,
    // and its sign is inverted (India is IST-5:30, not IST+5:30) because a POSIX
    // offset is the time to ADD to local time to reach UTC. newlib additionally
    // fails to reset an internal flag when TZ is replaced, so a second call can
    // leave the previous offset in force. Both failure modes are invisible from
    // the return value, hence the explicit measurement afterwards.
    void tz_apply(const std::string &tz)
    {
        if (tz.empty())
        {
            // Unset rather than set to a default: a unit that has never been told
            // where it is should report no local time instead of claiming UTC.
            unsetenv("TZ");
            tzset();
            ESP_LOGI(TAG, "timezone unset, reporting UTC only");
            return;
        }

        if (setenv("TZ", tz.c_str(), 1) != 0)
        {
            ESP_LOGE(TAG, "setenv(\"TZ\", \"%s\") failed", tz.c_str());
            return;
        }
        tzset();

        // A fixed, arbitrary instant, chosen away from any daylight-saving
        // transition so the reading cannot be confused by a rule we are not
        // implementing.
        const time_t probe = 1788301953; // 2026-10-01T06:12:33Z
        const int32_t offset = measure_utc_offset(probe);

        char text[32] = {0};
        format_offset(text, sizeof(text), offset);
        ESP_LOGI(TAG, "timezone \"%s\" applied, UTC offset is %s", tz.c_str(), text);
    }

    // lwIP has already committed the corrected time to the system clock by the
    // time this runs, so the job here is to record where the time came from and
    // hand the rest to the time task. Doing the I2C write here would block the
    // TCP/IP task for the length of a transfer, which is not a trade worth
    // making for a backup register.
    void sntp_sync_callback(struct timeval *tv)
    {
        if (tv == nullptr)
        {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            g_state.source = TimeSource::SNTP;
            g_state.established_ms = (uint64_t)(esp_timer_get_time() / 1000);
        }

        char utc_text[32] = {0};
        format_utc(utc_text, sizeof(utc_text), (time_t)tv->tv_sec);
        ESP_LOGI(TAG, "synchronized with %s, system clock set to %s", SNTP_SERVER, utc_text);
        xEventGroupSetBits(s_time_events, TIME_CTRL_EVENT_SYNCED);
    }

    // Copy the system clock into the RTC. The registers hold UTC, so the local
    // timezone is deliberately not applied here: that way a device that moves
    // between timezones does not have to be re-seeded.
    void rtc_store_now()
    {
        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            if (!g_state.rtc_present)
            {
                return;
            }
        }

        // The threshold has to be a time_t, not the bare year: compared against
        // one directly, 2024 is twenty seconds after the epoch and every real
        // time would sail past it.
        const time_t earliest = (time_t)(days_from_civil(RTC_MIN_PLAUSIBLE_YEAR, 1, 1) * 86400);
        const time_t now = time(nullptr);
        if (now < earliest)
        {
            // Nothing sensible to write. Storing an unset clock would only make
            // the next boot look plausible.
            ESP_LOGW(TAG, "not writing an implausible time to the RTC");
            return;
        }

        struct tm tm_utc = {};
        if (gmtime_r(&now, &tm_utc) == nullptr)
        {
            return;
        }

        if (pcf85063_write(&tm_utc) != ESP_OK)
        {
            // The time itself is still correct; only the RTC's own copy is stale,
            // and a later restart would be seeded from it.
            ESP_LOGW(TAG, "could not update the RTC, its copy of the time is stale");
            std::lock_guard<std::mutex> lock(g_state.mutex);
            g_state.rtc_valid = false;
        }
        else
        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            g_state.rtc_valid = true;
        }
    }

    // A restart seed, not an offline fallback: the part is on the 3v3 rail and this
    // board fits no backup source, so its contents survive a reset but not an
    // unplug. Only believed when the part's own power-loss flag is clear and the
    // calendar looks like this decade.
    void rtc_seed_system_clock()
    {
        struct tm tm_utc = {};
        if (pcf85063_read(&tm_utc) != ESP_OK)
        {
            return;
        }
        if ((tm_utc.tm_year + 1900) < RTC_MIN_PLAUSIBLE_YEAR)
        {
            ESP_LOGW(TAG, "RTC holds %04d-%02d-%02d, too old to trust, waiting for SNTP",
                     tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday);
            return;
        }

        const time_t when = utc_timegm(&tm_utc);
        struct timeval tv = {
            .tv_sec = when,
            .tv_usec = 0,
        };
        if (settimeofday(&tv, nullptr) != 0)
        {
            ESP_LOGW(TAG, "settimeofday() rejected the RTC time");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            g_state.source = TimeSource::RTC;
            g_state.established_ms = (uint64_t)(esp_timer_get_time() / 1000);
            g_state.rtc_valid = true;
        }

        ESP_LOGI(TAG, "system clock seeded from the RTC at %04d-%02d-%02d %02d:%02d:%02d UTC",
                 tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday, tm_utc.tm_hour, tm_utc.tm_min,
                 tm_utc.tm_sec);
    }

    // Owns both the SNTP handshake and the I2C writes, so neither the event loop
    // nor the TCP/IP task is ever blocked waiting on the network or the bus.
    void time_task(void *arg)
    {
        (void)arg;

        bool sntp_started = false;

        for (;;)
        {
            const EventBits_t bits =
                xEventGroupWaitBits(s_time_events, TIME_CTRL_EVENT_GOT_IP | TIME_CTRL_EVENT_SYNCED, pdFALSE,
                                    pdFALSE, portMAX_DELAY);

            if (bits & TIME_CTRL_EVENT_GOT_IP)
            {
                if (!sntp_started)
                {
                    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG(SNTP_SERVER);
                    // Corrections arrive one at a time rather than slewed in, so
                    // the value this device reports and the value stored in the
                    // RTC are the same the moment the callback runs.
                    config.smooth_sync = false;
                    config.wait_for_sync = true;
                    config.sync_cb = sntp_sync_callback;
                    // Kept running across an address change: lwIP re-queries on
                    // its own schedule, which is what keeps the RTC from drifting
                    // a long way between restarts.
                    config.start = true;

                    const esp_err_t err = esp_netif_sntp_init(&config);
                    if (err != ESP_OK)
                    {
                        ESP_LOGE(TAG, "esp_netif_sntp_init failed: %s", esp_err_to_name(err));
                    }
                    else
                    {
                        sntp_started = true;
                        ESP_LOGI(TAG, "SNTP started against %s", SNTP_SERVER);
                    }
                }
                else
                {
                    // Already initialised: restarting refreshes the server set
                    // after a network change, which esp_netif_sntp_init refuses
                    // to do a second time.
                    (void)esp_netif_sntp_start();
                }

                if (esp_netif_sntp_sync_wait(pdMS_TO_TICKS(SNTP_FIRST_SYNC_TIMEOUT_MS)) != ESP_OK)
                {
                    // Not a failure, and nothing falls back to a time: after a
                    // power cycle there is no RTC time to stand on either, and
                    // after a restart the seed was already applied. lwIP is still
                    // retrying; the clock is set by whichever attempt lands.
                    ESP_LOGW(TAG, "no SNTP correction within %d ms, still retrying in the "
                                  "background; the clock stays as it is until one lands",
                             SNTP_FIRST_SYNC_TIMEOUT_MS);
                }
            }

            if (bits & TIME_CTRL_EVENT_SYNCED)
            {
                rtc_store_now();
                // status_ctrl owns evt/status; this only asks it to republish so
                // the corrected time reaches anyone already subscribed.
                status_ctrl::publish();
            }

            // Consumed. Left set, a later address change would look like a fresh
            // correction and rewrite the RTC from a clock that had not moved.
            xEventGroupClearBits(s_time_events, bits);
        }
    }

    void got_ip_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
    {
        (void)arg;
        (void)event_base;
        (void)event_id;
        (void)event_data;

        xEventGroupSetBits(s_time_events, TIME_CTRL_EVENT_GOT_IP);
    }

    // Fill `obj` with the current time, or with a null "time" when nothing has
    // established it yet. The caller must not hold g_state.mutex.
    void time_fill(cJSON *obj)
    {
        TimeSource source;
        uint64_t established_ms;
        bool rtc_present;
        bool rtc_valid;
        std::string tz;

        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            source = g_state.source;
            established_ms = g_state.established_ms;
            rtc_present = g_state.rtc_present;
            rtc_valid = g_state.rtc_valid;
            tz = g_state.tz;
        }

        if (source == TimeSource::NONE)
        {
            // Null rather than a 1970 timestamp: an unestablished clock is not the
            // same fact as a clock reading the epoch, and only one of them is a bug.
            cJSON_AddNullToObject(obj, "utc");
            cJSON_AddNullToObject(obj, "epoch_s");
            cJSON_AddNullToObject(obj, "local");
            cJSON_AddNullToObject(obj, "tz");
            cJSON_AddStringToObject(obj, "source", time_source_to_string(source));
            cJSON_AddBoolToObject(obj, "synced", false);
            cJSON_AddNullToObject(obj, "age_ms");

            cJSON *rtc = cJSON_CreateObject();
            if (rtc != nullptr)
            {
                cJSON_AddBoolToObject(rtc, "present", rtc_present);
                cJSON_AddBoolToObject(rtc, "valid", rtc_valid);
                cJSON_AddItemToObject(obj, "rtc", rtc);
            }
            return;
        }

        const time_t now = time(nullptr);
        const uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000);

        char utc_text[32] = {0};
        format_utc(utc_text, sizeof(utc_text), now);
        cJSON_AddStringToObject(obj, "utc", utc_text);
        cJSON_AddNumberToObject(obj, "epoch_s", (double)now);

        if (tz.empty())
        {
            cJSON_AddNullToObject(obj, "local");
            cJSON_AddNullToObject(obj, "tz");
        }
        else
        {
            char local_text[40] = {0};
            format_local(local_text, sizeof(local_text), now);
            cJSON_AddStringToObject(obj, "local", local_text);
            cJSON_AddStringToObject(obj, "tz", tz.c_str());
        }

        cJSON_AddStringToObject(obj, "source", time_source_to_string(source));
        cJSON_AddBoolToObject(obj, "synced", source == TimeSource::SNTP);
        cJSON_AddNumberToObject(obj, "age_ms", (double)(now_ms - established_ms));

        cJSON *rtc = cJSON_CreateObject();
        if (rtc != nullptr)
        {
            cJSON_AddBoolToObject(rtc, "present", rtc_present);
            cJSON_AddBoolToObject(rtc, "valid", rtc_valid);
            cJSON_AddItemToObject(obj, "rtc", rtc);
        }
    }

} // namespace

void time_ctrl::init()
{
    s_time_events = xEventGroupCreate();

    mqtt_register_cmd(identity_topic_cmd_timezone(), time_ctrl::handle_timezone_command);

    // A dashboard that connects late, or reconnects after a broker restart, gets
    // the current time rather than whatever the retained copy said at boot.
    app::register_on_connect(
        []()
        {
            status_ctrl::publish();
        });
}

void time_ctrl::start()
{
    // The declared timezone first, so anything formatted from this point on,
    // including the seed log below, is already in the right zone. The stored
    // value wins over the compiled-in default, because config_store_load() has
    // already run by the time this is called.
    std::string tz;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        if (g_state.tz.empty())
        {
            g_state.tz = CONFIG_THELINK_TZ;
        }
        tz = g_state.tz;
    }
    tz_apply(tz);

    i2c_master_bus_handle_t bus = i2c_bsp_bus(ESP32_I2C_DEV_NUM);
    if (bus == nullptr)
    {
        ESP_LOGW(TAG, "no I2C bus, the RTC is unavailable and time will come from SNTP only");
    }
    else
    {
        if (pcf85063_init(bus, I2C_RTC_DEV_Address) == ESP_OK)
        {
            const bool valid = pcf85063_time_valid();
            std::lock_guard<std::mutex> lock(g_state.mutex);
            g_state.rtc_present = true;
            g_state.rtc_valid = valid;
        }
    }

    bool seed = false;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        seed = g_state.rtc_present && g_state.rtc_valid;
    }
    if (seed)
    {
        rtc_seed_system_clock();
    }
    else
    {
        // Said out loud, because "no time at boot" is otherwise indistinguishable
        // from a crash or an I2C fault. The usual cause is a power cycle: the part
        // has no backup source, so it comes back at the power-on default and only
        // SNTP can set the clock.
        ESP_LOGI(TAG, "boot seed skipped (RTC present=%s, holds a trustworthy time=%s); "
                      "the clock starts unset and time arrives with SNTP",
                 g_state.rtc_present ? "yes" : "no", g_state.rtc_valid ? "yes" : "no");
    }

    // Registered here rather than reused from provisioning so this module owns
    // its own trigger: an address arriving is exactly the event that makes NTP
    // meaningful, and the fact that provisioning also listens is incidental.
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &got_ip_handler, NULL));

    xTaskCreate(time_task, "time", 4096, NULL, 3, NULL);
}

void time_ctrl::handle_timezone_command(const char *payload)
{
    ESP_LOGI(TAG, "Timezone command received");

    cJSON *root = (payload != nullptr) ? cJSON_Parse(payload) : nullptr;
    if (root == nullptr)
    {
        ESP_LOGW(TAG, "timezone command was not valid JSON, expecting {\"tz\": \"IST-5:30\"}");
        return;
    }

    cJSON *tz_item = cJSON_GetObjectItemCaseSensitive(root, "tz");
    if (!cJSON_IsString(tz_item) || tz_item->valuestring == nullptr)
    {
        ESP_LOGW(TAG, "timezone command needs a \"tz\" string, e.g. {\"tz\": \"IST-5:30\"}");
        cJSON_Delete(root);
        return;
    }

    const std::string tz = tz_item->valuestring;
    cJSON_Delete(root);

    if (tz.size() >= 64)
    {
        ESP_LOGW(TAG, "timezone string is too long");
        return;
    }

    // An IANA name is the obvious thing to send and it does not work here, so it
    // is rejected with an explanation rather than accepted and then ignored.
    if (tz.find('/') != std::string::npos)
    {
        ESP_LOGW(TAG, "\"%s\" is an IANA zone name, which this C library cannot resolve. "
                      "Send a POSIX string instead, e.g. {\"tz\": \"IST-5:30\"}. Note the "
                      "inverted sign: the offset is the time to add to local time to reach UTC.",
                 tz.c_str());
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.tz = tz;
    }

    tz_apply(tz);
    config_store_save();
    status_ctrl::publish();
}

void time_ctrl::status_serialize(cJSON *root)
{
    cJSON *time = cJSON_CreateObject();
    if (time == nullptr)
    {
        ESP_LOGE(TAG, "out of memory building the time status");
        return;
    }

    time_fill(time);
    cJSON_AddItemToObject(root, "time", time);
}

void time_ctrl::config_serialize(cJSON *obj)
{
    std::lock_guard<std::mutex> lock(g_state.mutex);

    if (g_state.tz.empty())
    {
        cJSON_AddNullToObject(obj, "tz");
    }
    else
    {
        cJSON_AddStringToObject(obj, "tz", g_state.tz.c_str());
    }
}

void time_ctrl::config_apply(cJSON *obj)
{
    cJSON *tz_item = cJSON_GetObjectItemCaseSensitive(obj, "tz");
    if (!cJSON_IsString(tz_item) || tz_item->valuestring == nullptr)
    {
        return;
    }

    const std::string tz = tz_item->valuestring;
    if (tz.size() >= 64)
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.tz = tz;
    }
    tz_apply(tz);
    ESP_LOGI(TAG, "Restored timezone: %s", tz.c_str());
}
