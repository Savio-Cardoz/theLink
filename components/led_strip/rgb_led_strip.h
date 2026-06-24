/*
 * SPDX-FileCopyrightText: 2026 GitHub Copilot
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <map>
#include <functional>
#include <stdexcept>

#include "driver/rmt_tx.h"
#include "led_strip_encoder.h"

enum class rgb_pattern_t {
    SOLID_COLOR,
    RAINBOW_CYCLE,
    THEATER_CHASE,
    COLOR_WIPE,
    SCANNER,
    FADE,
};

// A static function that takes a string and returns a corresponding rgb_pattern_t enum value
static rgb_pattern_t pattern_from_string(const std::string &pattern_str)
{
    static const std::map<std::string, rgb_pattern_t> pattern_map = {
        {"solid_color", rgb_pattern_t::SOLID_COLOR},
        {"rainbow_cycle", rgb_pattern_t::RAINBOW_CYCLE},
        {"theater_chase", rgb_pattern_t::THEATER_CHASE},
        {"color_wipe", rgb_pattern_t::COLOR_WIPE},
        {"scanner", rgb_pattern_t::SCANNER},
        {"fade", rgb_pattern_t::FADE},
    };

    auto it = pattern_map.find(pattern_str);
    if (it != pattern_map.end()) {
        return it->second;
    } else {
        ESP_LOGE("RGB_LED_STRIP", "Invalid pattern string: %s", pattern_str.c_str());
        return rgb_pattern_t::SOLID_COLOR; // Default to SOLID_COLOR on error
    }
}

/**
 * @brief Template wrapper for an RGB LED strip driven by RMT.
 *
 * @tparam size Number of RGB pixels in the strip.
 */
template <size_t size>
class RgbLedStrip {
public:
    static_assert(size > 0, "RGB strip size must be greater than zero");

    /**
     * @brief Construct a new RgbLedStrip object and initialize RMT.
     *
     * @param gpio_num GPIO pin used for the LED strip data line.
     * @param resolution_hz RMT resolution in Hz.
     * @param mem_block_symbols Number of RMT memory symbols.
     * @param trans_queue_depth Depth of the transmit queue.
     */
    RgbLedStrip(gpio_num_t gpio_num,
                uint32_t resolution_hz = 10000000,
                uint32_t mem_block_symbols = 64,
                uint32_t trans_queue_depth = 4)
        : channel_(nullptr), encoder_(nullptr)
    {
        rmt_tx_channel_config_t tx_chan_config = {
            .gpio_num = gpio_num,
            .clk_src = RMT_CLK_SRC_DEFAULT,
            .resolution_hz = resolution_hz,
            .mem_block_symbols = mem_block_symbols,
            .trans_queue_depth = trans_queue_depth,
        };
        ESP_ERROR_CHECK(rmt_new_tx_channel(&tx_chan_config, &channel_));

        led_strip_encoder_config_t encoder_config = {
            .resolution = resolution_hz,
        };
        ESP_ERROR_CHECK(rmt_new_led_strip_encoder(&encoder_config, &encoder_));

        ESP_ERROR_CHECK(rmt_enable(channel_));
        pixel_data_.fill(0);
    }

    ~RgbLedStrip()
    {
        if (channel_ != nullptr) {
            rmt_disable(channel_);
            rmt_del_channel(channel_);
            channel_ = nullptr;
        }
    }

    /**
     * @brief Set the full strip to a single color using HSV values.
     *
     * @param h Hue in degrees [0, 360).
     * @param s Saturation in percent [0, 100].
     * @param v Value/brightness in percent [0, 100].
     */
    void setHsv(uint32_t h, uint32_t s, uint32_t v)
    {
        uint8_t r, g, b;
        hsv2rgb(h, s, v, r, g, b);
        setRgb(r, g, b);
    }

    /**
     * @brief Set a single pixel using HSV values.
     *
     * @param index Pixel index in the strip [0, size).
     * @param h Hue in degrees [0, 360).
     * @param s Saturation in percent [0, 100].
     * @param v Value/brightness in percent [0, 100].
     */
    void setHsvAt(size_t index, uint32_t h, uint32_t s, uint32_t v)
    {
        if (index >= size) {
            return;
        }
        uint8_t r, g, b;
        hsv2rgb(h, s, v, r, g, b);
        setRgbAt(index, r, g, b);
    }

    /**
     * @brief Send the currently configured pixel data to the LED strip.
     */
    void flush()
    {
        rmt_transmit_config_t tx_config = {
            .loop_count = 0,
        };
        ESP_ERROR_CHECK(rmt_transmit(channel_, encoder_, pixel_data_.data(), pixel_data_.size(), &tx_config));
        ESP_ERROR_CHECK(rmt_tx_wait_all_done(channel_, portMAX_DELAY));
    }

    /**
     * @brief Access the raw RGB pixel buffer.
     */
    const std::array<uint8_t, size * 3> &data() const
    {
        return pixel_data_;
    }

    /**
     * @brief Dispatch an enum value to the registered pattern handler.
     */
    void runPattern(rgb_pattern_t pattern, uint32_t h = 0, uint32_t s = 100, uint32_t v = 100)
    {
        auto it = pattern_map.find(pattern);
        if (it != pattern_map.end()) {
            it->second(*this, h, s, v);
        }
    }

private:
    static void hsv2rgb(uint32_t h, uint32_t s, uint32_t v, uint8_t &r, uint8_t &g, uint8_t &b)
    {
        h %= 360;
        uint32_t rgb_max = (v * 255U + 50U) / 100U;
        uint32_t rgb_min = (rgb_max * (100U - s) + 50U) / 100U;
        uint32_t i = h / 60U;
        uint32_t diff = h % 60U;
        uint32_t rgb_adj = ((rgb_max - rgb_min) * diff + 30U) / 60U;

        switch (i) {
            case 0:
                r = static_cast<uint8_t>(rgb_max);
                g = static_cast<uint8_t>(rgb_min + rgb_adj);
                b = static_cast<uint8_t>(rgb_min);
                break;
            case 1:
                r = static_cast<uint8_t>(rgb_max - rgb_adj);
                g = static_cast<uint8_t>(rgb_max);
                b = static_cast<uint8_t>(rgb_min);
                break;
            case 2:
                r = static_cast<uint8_t>(rgb_min);
                g = static_cast<uint8_t>(rgb_max);
                b = static_cast<uint8_t>(rgb_min + rgb_adj);
                break;
            case 3:
                r = static_cast<uint8_t>(rgb_min);
                g = static_cast<uint8_t>(rgb_max - rgb_adj);
                b = static_cast<uint8_t>(rgb_max);
                break;
            case 4:
                r = static_cast<uint8_t>(rgb_min + rgb_adj);
                g = static_cast<uint8_t>(rgb_min);
                b = static_cast<uint8_t>(rgb_max);
                break;
            default:
                r = static_cast<uint8_t>(rgb_max);
                g = static_cast<uint8_t>(rgb_min);
                b = static_cast<uint8_t>(rgb_max - rgb_adj);
                break;
        }
    }

    void setRgb(uint8_t r, uint8_t g, uint8_t b)
    {
        for (size_t i = 0; i < size; ++i) {
            setRgbAt(i, r, g, b);
        }
    }

    void setRgbAt(size_t index, uint8_t r, uint8_t g, uint8_t b)
    {
        const size_t offset = index * 3;
        pixel_data_[offset + 0] = g;
        pixel_data_[offset + 1] = r;
        pixel_data_[offset + 2] = b;
    }

    rmt_channel_handle_t channel_;
    rmt_encoder_handle_t encoder_;
    std::array<uint8_t, size * 3> pixel_data_;

    std::map<rgb_pattern_t, std::function<void(RgbLedStrip&, uint32_t, uint32_t, uint32_t)>> pattern_map = {
    {rgb_pattern_t::SOLID_COLOR, [](RgbLedStrip& strip, uint32_t h, uint32_t s, uint32_t v) {
        strip.setHsv(h, s, v);
        strip.flush();
    }},
    {rgb_pattern_t::RAINBOW_CYCLE, [](RgbLedStrip& strip, uint32_t h, uint32_t s, uint32_t v) {
        for (size_t i = 0; i < 16; ++i) {
            strip.setHsvAt(i, (h + i * 360 / 16) % 360, s, v);
        }
        strip.flush();
    }},
    {rgb_pattern_t::THEATER_CHASE, [](RgbLedStrip& strip, uint32_t h, uint32_t s, uint32_t v) {
        strip.setRgb(0, 0, 0);
        for (size_t i = 0; i < size; ++i) {
            if ((i + (h / 60U)) % 3U == 0U) {
                strip.setHsvAt(i, h, s, v);
            }
        }
        strip.flush();
    }},
    {rgb_pattern_t::COLOR_WIPE, [](RgbLedStrip& strip, uint32_t h, uint32_t s, uint32_t v) {
        strip.setRgb(0, 0, 0);
        const size_t wipe_index = (h / 30U) % size;
        strip.setHsvAt(wipe_index, h, s, v);
        strip.flush();
    }},
    {rgb_pattern_t::SCANNER, [](RgbLedStrip& strip, uint32_t h, uint32_t s, uint32_t v) {
        strip.setRgb(0, 0, 0);
        const size_t scan_index = (h / 30U) % ((2U * size) - 1U);
        const size_t position = scan_index >= size ? ((2U * size) - 2U - scan_index) : scan_index;
        strip.setHsvAt(position, h, s, v);
        strip.flush();
    }},
    {rgb_pattern_t::FADE, [](RgbLedStrip& strip, uint32_t h, uint32_t s, uint32_t v) {
        for (size_t i = 0; i < size; ++i) {
            const uint32_t fade_value = (v * static_cast<uint32_t>(size - i)) / static_cast<uint32_t>(size);
            strip.setHsvAt(i, h, s, fade_value);
        }
        strip.flush();
    }}
};
};
