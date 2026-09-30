#pragma once
#include "i_filesystem.hpp"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdmmc_host.h"

// The single place the card's mount point is spelled. Everything that needs the
// path — including app_main, which passes it down through SDCardConfig — reads
// it from here rather than repeating the literal.
constexpr const char *SD_MOUNT_POINT = "/sdcard";

// Configuration struct for dependency injection
struct SDCardConfig {
    std::string mountPoint; // e.g., "/sdcard"
    int maxOpenFiles;
    size_t allocationUnitSize;
    // Pin mappings (Assuming SDMMC 1-bit mode for simplicity, 
    // expand for 4-bit or SPI as needed)
    int pinCmd;
    int pinClk;
    int pinD0; 
};

/** 
 * @brief Manages SD card operations through ESP-IDF's VFS and SDMMC interfaces
 */
class SDCardManager : public IFileSystem {
public:
    SDCardManager(const SDCardConfig& config);
    ~SDCardManager() override;

    bool mount() override;
    void unmount() override;
    bool isMounted() const override;

    bool getSpaceInfo(uint64_t &totalBytes, uint64_t &freeBytes) const override;

    bool fileExists(const std::string& path) const override;
    bool deleteFile(const std::string& path) override;
    bool renameFile(const std::string& oldPath, const std::string& newPath) override;

    bool readTextFile(const std::string& path, std::string& outContent) override;
    bool writeTextFile(const std::string& path, const std::string& content) override;

private:
    SDCardConfig m_config;
    bool m_mounted;
    sdmmc_card_t* m_card;

    // The VFS path this card is mounted on, falling back to SD_MOUNT_POINT when
    // the caller did not supply one.
    const std::string &mountPath() const;

    // Helper to resolve absolute VFS paths
    std::string resolvePath(const std::string& filename) const;
};