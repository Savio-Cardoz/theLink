#include "data_downloader.hpp"
#include "esp_log.h"
#include "esp_http_client.h"
// #include "esp_cert_bundle.h"

static const char *TAG = "ASYNC_DL";

// --- Constants ---
constexpr size_t STREAM_BUFFER_SIZE = 8192; // 8KB overall buffer
constexpr size_t TRIGGER_LEVEL = 1024;      // Wake consumer at 1KB
constexpr size_t CHUNK_SIZE = 2048;         // HTTP read chunk size
constexpr uint32_t WDT_TIMEOUT_MS = 5000;   // Timeout for blocking operations

void AsyncDownloader::runStorageTask()
{
    uint8_t rxBuffer[CHUNK_SIZE];

    // Open file using standard C library (relies on FATFS/VFS being mounted)
    FILE *file = fopen(currentFilename.c_str(), "wb");
    if (!file)
    {
        ESP_LOGE(TAG, "Failed to open %s for writing!", currentFilename.c_str());
        isDownloadActive = false;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Storage Task: Opened %s", currentFilename.c_str());

    while (isDownloadActive || xStreamBufferBytesAvailable(streamBuffer) > 0)
    {
        size_t bytesReceived = xStreamBufferReceive(
            streamBuffer,
            rxBuffer,
            sizeof(rxBuffer),
            pdMS_TO_TICKS(100) // Wake up frequently to check isDownloadActive
        );

        if (bytesReceived > 0)
        {
            size_t written = fwrite(rxBuffer, 1, bytesReceived, file);
            if (written != bytesReceived)
            {
                ESP_LOGE(TAG, "Storage Task: Write failed! SD Card full or removed?");
                isDownloadActive = false; // Abort download
                break;
            }
        }
    }

    fclose(file);
    ESP_LOGI(TAG, "Storage Task: File closed. Shutting down.");

    storageTaskHandle = nullptr;
    vTaskDelete(NULL);
}

void AsyncDownloader::runHttpTask()
{
    uint8_t txBuffer[CHUNK_SIZE];
    ESP_LOGI(TAG, "HTTP Task: Starting download from %s", currentUrl.c_str());

    // 1. Configure the HTTP Client
    esp_http_client_config_t config = {};
    config.url = currentUrl.c_str();
    // IMPORTANT: For production HTTPS, you must provide a CA certificate!
    // config.cert_pem = (const char *)ca_cert_pem_start;
    // config.crt_bundle_attach = esp_crt_bundle_attach; // Uses ESP-IDF default cert bundle
    config.timeout_ms = 10000;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client)
    {
        ESP_LOGE(TAG, "HTTP Task: Failed to initialize client");
        isDownloadActive = false;
        vTaskDelete(NULL);
        return;
    }

    // 2. Open the connection manually (bypasses the event handler)
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "HTTP Task: Failed to open connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        isDownloadActive = false;
        vTaskDelete(NULL);
        return;
    }

    // 3. Fetch headers to get the file size
    int content_length = esp_http_client_fetch_headers(client);
    if (content_length <= 0)
    {
        ESP_LOGW(TAG, "HTTP Task: Server didn't provide content length. Streaming until EOF.");
    }
    else
    {
        ESP_LOGI(TAG, "HTTP Task: File size is %d bytes", content_length);
    }

    // 4. Read the data chunk by chunk
    int totalBytesDownloaded = 0;
    while (true)
    {
        if (!isDownloadActive)
        {
            ESP_LOGW(TAG, "HTTP Task: Download aborted by storage task.");
            break;
        }

        int bytesRead = esp_http_client_read(client, (char *)txBuffer, CHUNK_SIZE);

        if (bytesRead < 0)
        {
            ESP_LOGE(TAG, "HTTP Task: Read error!");
            break;
        }
        else if (bytesRead == 0)
        {
            ESP_LOGI(TAG, "HTTP Task: End of file reached.");
            break; // EOF
        }

        // Push to stream buffer. This blocks if the SD card is currently stalling.
        size_t bytesSent = xStreamBufferSend(
            streamBuffer,
            txBuffer,
            bytesRead,
            pdMS_TO_TICKS(WDT_TIMEOUT_MS));

        if (bytesSent != bytesRead)
        {
            ESP_LOGE(TAG, "HTTP Task: Stream buffer full! Storage task is frozen.");
            break;
        }

        totalBytesDownloaded += bytesRead;
    }

    // 5. Clean up HTTP resources
    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    ESP_LOGI(TAG, "HTTP Task: Complete. Total downloaded: %d. Signaling storage task.", totalBytesDownloaded);

    // Signal storage task to finish up
    isDownloadActive = false;
    httpTaskHandle = nullptr;
    vTaskDelete(NULL);
}

AsyncDownloader::AsyncDownloader()
{
    streamBuffer = xStreamBufferCreate(STREAM_BUFFER_SIZE, TRIGGER_LEVEL);
    if (streamBuffer == nullptr)
    {
        ESP_LOGE(TAG, "Failed to create stream buffer! Out of heap.");
    }
}

AsyncDownloader::~AsyncDownloader()
{
    if (streamBuffer != nullptr)
    {
        vStreamBufferDelete(streamBuffer);
    }
}

// --- 3. The Orchestrator ---
bool AsyncDownloader::startDownload(const std::string &url, const std::string &filename)
{
    if (isDownloadActive)
    {
        ESP_LOGW(TAG, "Download already in progress!");
        return false;
    }

    currentUrl = url;
    currentFilename = filename;
    isDownloadActive = true;

    xStreamBufferReset(streamBuffer);

    // Spawn Storage Task
    xTaskCreate(storageTaskWrapper, "StorageTask", 4096, this, 5, &storageTaskHandle);

    // Spawn HTTP Task
    xTaskCreate(httpTaskWrapper, "HttpTask", 8192, this, 4, &httpTaskHandle);

    return true;
}