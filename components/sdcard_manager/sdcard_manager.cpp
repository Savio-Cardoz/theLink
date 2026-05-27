#include "sdcard_manager.hpp"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "driver/sdmmc_host.h"
#include "sdmmc_cmd.h"

#define SD_MOUNT_POINT "/sdcard" // Default mount point for the SD card
#define SD_MAX_OPEN_FILES 5
#define SD_ALLOCATION_UNIT_SIZE (16 * 1024 * 3) // 48 KB, similar to a sector size

static const char *TAG = "SD_MANAGER";

SDCardManager::SDCardManager(const SDCardConfig &config)
    : m_config(config), m_mounted(false), m_card(nullptr) {}

SDCardManager::~SDCardManager()
{
    if (m_mounted)
    {
        unmount();
    }
}

bool SDCardManager::mount()
{
    if (m_mounted)
    {
        ESP_LOGW(TAG, "SD card is already mounted.");
        return true;
    }

    ESP_LOGI(TAG, "Initializing SDMMC peripheral in 1-bit mode...");

    // 1. Configure the SDMMC host driver
    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    // Optional: If you encounter signal integrity issues on your custom PCB,
    // you can lower the frequency (e.g., host.max_freq_khz = SDMMC_FREQ_PROBING;)
    host.max_freq_khz = SDMMC_FREQ_HIGHSPEED; // Use high-speed mode (up to 50 MHz)

    // 2. Configure the SDMMC slot
    sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();
    slot_config.width = 1; // Enforce 1-bit mode (D0 only)

    // ESP32-S3 allows routing SDMMC signals via the GPIO matrix
    slot_config.clk = (gpio_num_t)m_config.pinClk;
    slot_config.cmd = (gpio_num_t)m_config.pinCmd;
    slot_config.d0 = (gpio_num_t)m_config.pinD0;

    // Enable internal pull-ups on CMD and D0. (Hardware pull-ups are still recommended!)
    slot_config.flags |= SDMMC_SLOT_FLAG_INTERNAL_PULLUP;

    // 3. Configure the VFS FAT mount options
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {};
    mount_config.format_if_mount_failed = false; // Protect rollback binaries!
    mount_config.max_files = m_config.maxOpenFiles;
    mount_config.allocation_unit_size = m_config.allocationUnitSize; // Use larger allocation unit for better performance

    // 4. Mount the filesystem
    esp_err_t ret = esp_vfs_fat_sdmmc_mount(SD_MOUNT_POINT, &host, &slot_config, &mount_config, &m_card);

    if (ret != ESP_OK)
    {
        if (ret == ESP_FAIL)
        {
            ESP_LOGE(TAG, "Failed to mount filesystem. Corrupted FAT or unformatted card.");
        }
        else
        {
            ESP_LOGE(TAG, "Failed to initialize the card (%s). "
                          "Check wiring and pull-up resistors.",
                     esp_err_to_name(ret));
        }
        return false;
    }

    ESP_LOGI(TAG, "SD card mounted successfully at %s", SD_MOUNT_POINT);
    sdmmc_card_print_info(stdout, m_card);

    m_mounted = true;
    return true;
}

void SDCardManager::unmount()
{
    if (!m_mounted)
    {
        return;
    }

    ESP_LOGI(TAG, "Unmounting SD card...");

    // Unmount the partition and tear down the SDMMC host
    esp_err_t ret = esp_vfs_fat_sdcard_unmount(SD_MOUNT_POINT, m_card);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to unmount SD card. Error: %s", esp_err_to_name(ret));
    }

    m_card = nullptr;
    m_mounted = false;
    ESP_LOGI(TAG, "SD card unmounted.");
}

bool SDCardManager::isMounted() const
{
    return m_mounted;
}

std::string SDCardManager::resolvePath(const std::string &filename) const
{
    // Combine the VFS mount point (e.g., "/sdcard") with the filename
    // Ensure we don't double up on slashes if filename already has one
    if (!filename.empty() && filename[0] == '/')
    {
        return std::string(SD_MOUNT_POINT) + filename;
    }
    return std::string(SD_MOUNT_POINT) + "/" + filename;
}

bool SDCardManager::readTextFile(const std::string &path, std::string &outContent)
{
    if (!m_mounted)
    {
        ESP_LOGE("SD_MANAGER", "Cannot read file, SD card is not mounted.");
        return false;
    }

    std::string fullPath = resolvePath(path);
    ESP_LOGI("SD_MANAGER", "Reading file: %s", fullPath.c_str());

    // Open file in read-only text mode
    FILE *file = fopen(fullPath.c_str(), "r");
    if (file == nullptr)
    {
        ESP_LOGE("SD_MANAGER", "Failed to open file: %s", fullPath.c_str());
        return false;
    }

    // Determine file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (size < 0)
    {
        ESP_LOGE("SD_MANAGER", "Failed to get file size.");
        fclose(file);
        return false;
    }

    // Read the file into the string
    outContent.resize(size);
    size_t bytesRead = fread(&outContent[0], 1, size, file);
    fclose(file);

    if (bytesRead != size)
    {
        ESP_LOGE("SD_MANAGER", "File read incomplete. Read %zu of %ld bytes.", bytesRead, size);
        return false;
    }

    return true;
}

bool SDCardManager::writeTextFile(const std::string &path, const std::string &content)
{
    if (!m_mounted)
    {
        ESP_LOGE("SD_MANAGER", "Cannot write file, SD card is not mounted.");
        return false;
    }

    std::string fullPath = resolvePath(path);
    ESP_LOGI("SD_MANAGER", "Writing to file: %s", fullPath.c_str());

    // Open file in write-only text mode (this will create or overwrite the file)
    FILE *file = fopen(fullPath.c_str(), "w");
    if (file == nullptr)
    {
        ESP_LOGE("SD_MANAGER", "Failed to open file for writing: %s", fullPath.c_str());
        return false;
    }

    size_t bytesWritten = fwrite(content.data(), 1, content.size(), file);
    fclose(file);

    if (bytesWritten != content.size())
    {
        ESP_LOGE("SD_MANAGER", "File write incomplete. Wrote %zu of %zu bytes.", bytesWritten, content.size());
        return false;
    }

    return true;
}

bool SDCardManager::fileExists(const std::string &path) const
{
    if (!m_mounted)
    {
        ESP_LOGE("SD_MANAGER", "Cannot check file existence, SD card is not mounted.");
        return false;
    }

    std::string fullPath = resolvePath(path);
    FILE *file = fopen(fullPath.c_str(), "r");
    if (file)
    {
        fclose(file);
        return true;
    }
    return false;
}

bool SDCardManager::deleteFile(const std::string &path)
{
    if (!m_mounted)
    {
        ESP_LOGE("SD_MANAGER", "Cannot delete file, SD card is not mounted.");
        return false;
    }

    std::string fullPath = resolvePath(path);
    if (remove(fullPath.c_str()) == 0)
    {
        return true;
    }
    else
    {
        ESP_LOGE("SD_MANAGER", "Failed to delete file: %s", fullPath.c_str());
        return false;
    }
}

bool SDCardManager::renameFile(const std::string &oldPath, const std::string &newPath)
{
    if (!m_mounted)
    {
        ESP_LOGE("SD_MANAGER", "Cannot rename file, SD card is not mounted.");
        return false;
    }

    std::string fullOldPath = resolvePath(oldPath);
    std::string fullNewPath = resolvePath(newPath);

    if (rename(fullOldPath.c_str(), fullNewPath.c_str()) == 0)
    {
        return true;
    }
    else
    {
        ESP_LOGE("SD_MANAGER", "Failed to rename file from %s to %s", fullOldPath.c_str(), fullNewPath.c_str());
        return false;
    }
}