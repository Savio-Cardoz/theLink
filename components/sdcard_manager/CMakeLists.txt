idf_component_register(SRCS "sdcard_manager.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES fatfs sdmmc driver)