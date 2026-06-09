#ifndef __data_downloader_hpp__
#define __data_downloader_hpp__

#include <string>
#include "freertos/FreeRTOS.h"
#include "freertos/stream_buffer.h"
#include "freertos/task.h"
#include <atomic>
#include <functional>

class AsyncDownloader
{
public:
    // Define a callback type: void callback(bool success, std::string filename)
    using DownloadCallback_t = std::function<void(bool, const std::string &)>;

    AsyncDownloader();
    ~AsyncDownloader();

    bool startDownload(const std::string &url, const std::string &filename, DownloadCallback_t callback = nullptr);

private:
    DownloadCallback_t onCompleteCallback{nullptr};
    StreamBufferHandle_t streamBuffer = nullptr;
    TaskHandle_t storageTaskHandle = nullptr;
    TaskHandle_t httpTaskHandle = nullptr;

    std::atomic<bool> isDownloadActive{false};
    std::string currentFilename;
    std::string currentUrl;

    void runHttpTask();
    void runStorageTask();

    // --- 1. The Consumer (Storage Task) ---
    static void storageTaskWrapper(void *param)
    {
        AsyncDownloader *instance = static_cast<AsyncDownloader *>(param);
        instance->runStorageTask();
    }

    // --- 2. The Producer (HTTP Task) ---
    static void httpTaskWrapper(void *param)
    {
        AsyncDownloader *instance = static_cast<AsyncDownloader *>(param);
        instance->runHttpTask();
    }
};

#endif // __data_downloader_hpp__