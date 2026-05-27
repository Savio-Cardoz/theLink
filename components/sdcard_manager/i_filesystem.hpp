#pragma once
// #include <cstdint>
// #include <cstddef>
#include <string>

/** 
 * @brief Abstract interface for file system operations
 */
class IFileSystem {
public:
    virtual ~IFileSystem() = default;

    // Hardware / Mount management
    virtual bool mount() = 0;
    virtual void unmount() = 0;
    virtual bool isMounted() const = 0;

    // Core File Operations
    virtual bool fileExists(const std::string& path) const = 0;
    virtual bool deleteFile(const std::string& path) = 0;
    
    // Atomic rename is critical for our manifest safety (tmp -> json)
    virtual bool renameFile(const std::string& oldPath, const std::string& newPath) = 0;

    // High-level read/write for small files (like manifest.json)
    virtual bool readTextFile(const std::string& path, std::string& outContent) = 0;
    virtual bool writeTextFile(const std::string& path, const std::string& content) = 0;

    // Note: For large OTA binary flashing, we will use standard fopen/fread 
    // inside the Factory app to stream data, rather than loading 4MB into RAM.
};