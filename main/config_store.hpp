#pragma once

// Persist the display path + notification LED state to /sdcard/config.json
// (save) and restore it (load). The module only knows how to read/write the
// file: field serialization is delegated to each owning subsystem.

void config_store_save(void);
void config_store_load(void);