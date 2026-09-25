#pragma once

#include <cstdint>

#include "cJSON.h"
#include "esp_log.h"
#include "rgb_led_strip.h"

// Pure colour-mapping helpers shared across the LED subsystem. Single source
// of truth for the string/enum names, range clamping and colour parsing.

const char *pattern_to_string(rgb_pattern_t pattern);

uint32_t clamp_u(long long value, long long lo, long long hi);

// Parse "#RRGGBB" (or "RRGGBB").
bool hex_to_rgb(const char *str, uint8_t &r, uint8_t &g, uint8_t &b);

// Parsed colour: valid flag + both HSV (uniform internal form) and RGB.
struct led_color_t {
	bool valid = false;
	uint32_t h = 0;
	uint32_t s = 0;
	uint32_t v = 0;
	uint8_t r = 0;
	uint8_t g = 0;
	uint8_t b = 0;
};

// Accepts "#RRGGBB" (or "RRGGBB"), {h,s,v} (h 0-360, s/v 0-100), or {r,g,b}.
led_color_t parse_led_color(cJSON *item);