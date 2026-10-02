#include <string.h>

#include "esp_log.h"

#include "pcf85063_bsp.h"

static const char *TAG = "PCF85063";

#define PCF85063_XFER_TIMEOUT_MS 100

static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev;
static uint8_t s_addr;

// Every calendar field is BCD, and so is the pair of nibbles in every register.
// Validating both nibbles separately is what stops a bus glitch from turning
// into a plausible-looking date: 0x5A would decode to 70 minutes otherwise.
static uint8_t pcf85063_bcd_to_bin(uint8_t bcd, uint8_t max)
{
    const uint8_t hi = (uint8_t)(bcd >> 4);
    const uint8_t lo = (uint8_t)(bcd & 0x0F);
    if (hi > 9 || lo > 9)
    {
        return 0xFF;
    }
    const uint8_t value = (uint8_t)(hi * 10 + lo);
    return (value > max) ? 0xFF : value;
}

static uint8_t pcf85063_bin_to_bcd(uint8_t value)
{
    return (uint8_t)(((value / 10) << 4) | (value % 10));
}

// Reading a register is the one operation every entry point needs, and the
// driver reports every kind of failure as ESP_ERR_INVALID_STATE, so the caller
// gets no clue from the error code which address or transfer failed. Logging
// here keeps that diagnosis in one place.
static esp_err_t pcf85063_read_reg(uint8_t reg, uint8_t *data, size_t len, const char *what)
{
    const esp_err_t err = i2c_master_transmit_receive(s_dev, &reg, 1, data, len, PCF85063_XFER_TIMEOUT_MS);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "%s read of %zu byte(s) from 0x%02X failed (%s)", what, len, reg, esp_err_to_name(err));
    }
    return err;
}

esp_err_t pcf85063_init(i2c_master_bus_handle_t bus, uint8_t dev_addr)
{
    if (bus == NULL)
    {
        ESP_LOGE(TAG, "I2C bus handle is NULL");
        return ESP_ERR_INVALID_ARG;
    }

    if (s_dev != NULL)
    {
        return ESP_OK;
    }

    i2c_device_config_t dev_config = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = dev_addr,
        .scl_speed_hz = PCF85063_I2C_SPEED_HZ,
    };

    const esp_err_t err = i2c_master_bus_add_device(bus, &dev_config, &s_dev);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to add device at 0x%02X: %s", dev_addr, esp_err_to_name(err));
        s_dev = NULL;
        return err;
    }

    s_bus = bus;
    s_addr = dev_addr;

    // Prove the part really answers before reporting it attached, and log the one
    // bit that decides whether its stored time is usable. A unit with no backup
    // rail sets OS on every boot, and that is invisible from the status payload
    // unless it is said out loud here.
    uint8_t ctrl1 = 0;
    if (pcf85063_read_reg(PCF85063_REG_CONTROL_1, &ctrl1, 1, "Control_1") == ESP_OK)
    {
        ESP_LOGI(TAG, "attached at 0x%02X, Control_1 0x%02X%s", dev_addr, ctrl1,
                 (ctrl1 & PCF85063_CTRL1_STOP) ? ", divider held in reset" : "");
    }

    ESP_LOGI(TAG, "PCF85063 attached at 0x%02X", dev_addr);
    return ESP_OK;
}

bool pcf85063_present(void)
{
    if (s_bus == NULL)
    {
        return false;
    }
    const esp_err_t err = i2c_master_probe(s_bus, s_addr, PCF85063_XFER_TIMEOUT_MS);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "nothing acknowledged at 0x%02X (%s)", s_addr, esp_err_to_name(err));
        return false;
    }
    ESP_LOGI(TAG, "0x%02X acknowledged on the shared I2C bus", s_addr);
    return true;
}

// The raw date/time block, fetched in one transfer. The OS bit rides in the
// seconds register, so this single read answers both "is the clock running" and
// "what time is it".
static esp_err_t pcf85063_read_datetime(uint8_t raw[PCF85063_DATETIME_REG_COUNT])
{
    return pcf85063_read_reg(PCF85063_DATETIME_FIRST_REG, raw, PCF85063_DATETIME_REG_COUNT, "date/time");
}

static esp_err_t pcf85063_decode(const uint8_t raw[PCF85063_DATETIME_REG_COUNT], struct tm *out)
{
    const uint8_t sec = pcf85063_bcd_to_bin((uint8_t)(raw[0] & 0x7F), 59);
    const uint8_t min = pcf85063_bcd_to_bin(raw[1], 59);
    const uint8_t hour = pcf85063_bcd_to_bin((uint8_t)(raw[2] & 0x3F), 23);
    const uint8_t day = pcf85063_bcd_to_bin(raw[3], 31);
    const uint8_t month = pcf85063_bcd_to_bin((uint8_t)(raw[5] & 0x1F), 12);
    const uint8_t year = pcf85063_bcd_to_bin(raw[6], 99);

    if (sec > 59 || min > 59 || hour > 23 || day < 1 || day > 31 || month < 1 || month > 12)
    {
        ESP_LOGW(TAG, "date/time register block is not valid BCD: %02x %02x %02x %02x %02x %02x %02x",
                 raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6]);
        return ESP_ERR_INVALID_RESPONSE;
    }

    out->tm_sec = sec;
    out->tm_min = min;
    out->tm_hour = hour;
    out->tm_mday = day;
    // Datasheet table 8.3.5: the weekday register is plain binary 0-6, not BCD,
    // and is purely informational, so it is passed through as read.
    out->tm_wday = (int)(raw[4] & 0x07);
    out->tm_mon = (int)month - 1; // C wants 0-11, the part stores 1-12
    out->tm_year = (int)year + 100; // two-digit year, and 1900 + 100 = 2000
    out->tm_yday = 0;
    out->tm_isdst = 0;
    return ESP_OK;
}

bool pcf85063_time_valid(void)
{
    if (s_dev == NULL)
    {
        return false;
    }

    uint8_t raw[PCF85063_DATETIME_REG_COUNT] = {0};
    if (pcf85063_read_datetime(raw) != ESP_OK)
    {
        return false;
    }

    // Datasheet section 8.3.1: OS is set by the power-on reset and whenever the
    // oscillator stops, and only software clears it. A set bit means the stored
    // time is the power-on default, not a real time.
    if (raw[0] & PCF85063_SECONDS_OS)
    {
        ESP_LOGI(TAG, "OS is set, so this is a part that has lost power since it was set");
        return false;
    }

    struct tm decoded = {0};
    if (pcf85063_decode(raw, &decoded) != ESP_OK)
    {
        ESP_LOGW(TAG, "stored date/time is not a valid calendar, not seeding from it");
        return false;
    }

    // A part that has never been written reads back 1 January 2000 with OS set,
    // so OS is the real test. The year floor is a second, cheap guard against a
    // cell that has held a plausible but wrong date for years.
    if ((decoded.tm_year + 1900) < 2024)
    {
        ESP_LOGI(TAG, "stored calendar is %04d, before the plausible floor, not seeding from it",
                 decoded.tm_year + 1900);
        return false;
    }

    return true;
}

esp_err_t pcf85063_read(struct tm *out)
{
    if (s_dev == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }
    if (out == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t raw[PCF85063_DATETIME_REG_COUNT] = {0};
    const esp_err_t err = pcf85063_read_datetime(raw);
    if (err != ESP_OK)
    {
        return err;
    }

    if (raw[0] & PCF85063_SECONDS_OS)
    {
        ESP_LOGW(TAG, "OS is set at 0x%02X, the stored time is not trustworthy", s_addr);
        return ESP_ERR_INVALID_STATE;
    }

    return pcf85063_decode(raw, out);
}

esp_err_t pcf85063_write(const struct tm *t)
{
    if (s_dev == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }
    if (t == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (t->tm_sec > 59 || t->tm_min > 59 || t->tm_hour > 23 || t->tm_mday < 1 || t->tm_mday > 31 ||
        t->tm_mon < 0 || t->tm_mon > 11 || t->tm_year < 100)
    {
        ESP_LOGE(TAG, "refusing to write an out-of-range calendar to the clock");
        return ESP_ERR_INVALID_ARG;
    }

    // Hold the divider in reset so the counter does not advance underneath the
    // seven register writes, which would otherwise cost up to a second.
    uint8_t ctrl1 = 0;
    if (pcf85063_read_reg(PCF85063_REG_CONTROL_1, &ctrl1, 1, "Control_1") != ESP_OK)
    {
        return ESP_FAIL;
    }
    // EXT_TEST must be cleared to leave test mode, and STOP must be set. Read
    // modify write keeps CAP_SEL, which selects the crystal load capacitance and
    // must not be disturbed.
    const uint8_t hold = (uint8_t)((ctrl1 & (uint8_t)~PCF85063_CTRL1_EXT_TEST) | PCF85063_CTRL1_STOP);
    const uint8_t set[2] = {PCF85063_REG_CONTROL_1, hold};
    esp_err_t err = i2c_master_transmit(s_dev, set, sizeof(set), PCF85063_XFER_TIMEOUT_MS);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "could not hold the divider in reset (%s)", esp_err_to_name(err));
        return err;
    }

    const uint8_t year = (uint8_t)(t->tm_year - 100);
    uint8_t block[PCF85063_DATETIME_REG_COUNT];
    // Bit 7 of the seconds register is OS, not part of the value: writing the
    // BCD seconds with that bit clear is what acknowledges a power-on reset.
    block[0] = pcf85063_bin_to_bcd((uint8_t)t->tm_sec);
    block[1] = pcf85063_bin_to_bcd((uint8_t)t->tm_min);
    block[2] = pcf85063_bin_to_bcd((uint8_t)t->tm_hour);
    block[3] = pcf85063_bin_to_bcd((uint8_t)t->tm_mday);
    block[4] = (uint8_t)(t->tm_wday & 0x07);
    block[5] = pcf85063_bin_to_bcd((uint8_t)(t->tm_mon + 1));
    block[6] = pcf85063_bin_to_bcd(year);

    // Register and payload in one transfer so the auto-increment address lands
    // on 0x04 and the block is written as the single frozen write the part wants.
    uint8_t tx[1 + PCF85063_DATETIME_REG_COUNT];
    tx[0] = PCF85063_DATETIME_FIRST_REG;
    memcpy(&tx[1], block, sizeof(block));
    err = i2c_master_transmit(s_dev, tx, sizeof(tx), PCF85063_XFER_TIMEOUT_MS);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "date/time write NACKed at 0x%02X (%s)", s_addr, esp_err_to_name(err));
        return err;
    }

    // Release the divider as a separate transfer: the TP register space is only
    // 0x00-0x0A, so the address auto-increment cannot be relied on to wrap here.
    const uint8_t release[2] = {PCF85063_REG_CONTROL_1, (uint8_t)(hold & (uint8_t)~PCF85063_CTRL1_STOP)};
    err = i2c_master_transmit(s_dev, release, sizeof(release), PCF85063_XFER_TIMEOUT_MS);
    if (err != ESP_OK)
    {
        // The time is stored, but the divider is still held. Say so loudly: the
        // clock would silently stay frozen.
        ESP_LOGE(TAG, "stored the time but could not release the divider at 0x%02X (%s), the RTC is stopped",
                 s_addr, esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "clock set to %04d-%02d-%02d %02d:%02d:%02d UTC", t->tm_year + 1900, t->tm_mon + 1,
             t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
    return ESP_OK;
}

void pcf85063_deinit(void)
{
    if (s_dev != NULL)
    {
        i2c_master_bus_rm_device(s_dev);
        s_dev = NULL;
    }
    s_bus = NULL;
    s_addr = PCF85063_DEFAULT_I2C_ADDR;
}
