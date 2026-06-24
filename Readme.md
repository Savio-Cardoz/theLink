

### Note: build Minimal version of LVGL. Enable LVGL Minimal Configuration to save heap memory.

### Version 0.2.0
-   Added the RGB LED strip control via MQTT message
-   {
        "type": "notification",
        "data": {
            "download": "null",
            "filename": "null",
            "message": "scanner"
        }
    }
-   The RgbLedStrip class has a public interface run_pattern() that takes a pattern string input to start the RGB Led Strip.
-   The "message" field of the MQTT message has to be any one of the enums defined under rgb_pattern_t to be drawn on the LED strip.


### Version 0.1.0
Enable CONFIG_MQTT_PROTOCOL_5

{
    "type":"LED",   
    "data": {
        "download":"domain.com",
        "filename":"file.bin"
    }
}

1. Add RGB control component
2. Upload factory updater firmware and test binary download and update functionality
3. Long run test. Functional Test
4. Body design and construction
5. Clay skeleton 
6. Base clay structure
7. Final top clay layer.
8. Paint.