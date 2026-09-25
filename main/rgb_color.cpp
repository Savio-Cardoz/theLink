#include <cstdlib>

#include "app_common.hpp"
#include "rgb_color.hpp"

const char *pattern_to_string(rgb_pattern_t pattern)
{
	switch (pattern)
	{
	case rgb_pattern_t::OFF: return "off";
	case rgb_pattern_t::SOLID_COLOR: return "solid_color";
	case rgb_pattern_t::RAINBOW_CYCLE: return "rainbow_cycle";
	case rgb_pattern_t::THEATER_CHASE: return "theater_chase";
	case rgb_pattern_t::COLOR_WIPE: return "color_wipe";
	case rgb_pattern_t::SCANNER: return "scanner";
	case rgb_pattern_t::FADE: return "fade";
	}
	return "solid_color";
}

uint32_t clamp_u(long long value, long long lo, long long hi)
{
	if (value < lo) value = lo;
	if (value > hi) value = hi;
	return static_cast<uint32_t>(value);
}

bool hex_to_rgb(const char *str, uint8_t &r, uint8_t &g, uint8_t &b)
{
	if (str == nullptr)
	{
		return false;
	}
	const char *p = str;
	while (*p == ' ' || *p == '\t') p++;
	if (*p == '#') p++;

	size_t len = 0;
	while (p[len] != '\0' && p[len] != ' ' && p[len] != '\t') len++;
	if (len != 6)
	{
		return false;
	}

	char *endptr = nullptr;
	unsigned long val = strtoul(p, &endptr, 16);
	if (endptr == p || *endptr != '\0')
	{
		return false;
	}
	r = static_cast<uint8_t>((val >> 16) & 0xFF);
	g = static_cast<uint8_t>((val >> 8) & 0xFF);
	b = static_cast<uint8_t>(val & 0xFF);
	return true;
}

led_color_t parse_led_color(cJSON *item)
{
	if (cJSON_IsString(item) && item->valuestring != NULL)
	{
		uint8_t r, g, b;
		if (hex_to_rgb(item->valuestring, r, g, b))
		{
			led_color_t out;
			out.valid = true;
			out.r = r; out.g = g; out.b = b;
			RgbLedStrip<app::LED_COUNT>::rgb2hsv(r, g, b, out.h, out.s, out.v);
			return out;
		}
		return {};
	}

	if (cJSON_IsObject(item))
	{
		cJSON *h = cJSON_GetObjectItemCaseSensitive(item, "h");
		cJSON *s = cJSON_GetObjectItemCaseSensitive(item, "s");
		cJSON *v = cJSON_GetObjectItemCaseSensitive(item, "v");
		if (cJSON_IsNumber(h) && cJSON_IsNumber(s) && cJSON_IsNumber(v))
		{
			led_color_t out;
			out.valid = true;
			out.h = clamp_u(h->valueint, 0, 359);
			out.s = clamp_u(s->valueint, 0, 100);
			out.v = clamp_u(v->valueint, 0, 100);
			RgbLedStrip<app::LED_COUNT>::hsv2rgb(out.h, out.s, out.v, out.r, out.g, out.b);
			return out;
		}

		cJSON *r = cJSON_GetObjectItemCaseSensitive(item, "r");
		cJSON *g = cJSON_GetObjectItemCaseSensitive(item, "g");
		cJSON *b = cJSON_GetObjectItemCaseSensitive(item, "b");
		if (cJSON_IsNumber(r) && cJSON_IsNumber(g) && cJSON_IsNumber(b))
		{
			led_color_t out;
			out.valid = true;
			out.r = static_cast<uint8_t>(clamp_u(r->valueint, 0, 255));
			out.g = static_cast<uint8_t>(clamp_u(g->valueint, 0, 255));
			out.b = static_cast<uint8_t>(clamp_u(b->valueint, 0, 255));
			RgbLedStrip<app::LED_COUNT>::rgb2hsv(out.r, out.g, out.b, out.h, out.s, out.v);
			return out;
		}
	}

	return {};
}