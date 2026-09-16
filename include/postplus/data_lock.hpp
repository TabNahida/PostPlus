#pragma once
#include <filesystem>
#include <memory>

namespace postplus {
// Reject a symbolic link or Windows reparse point at the specified target.
// Callers check the data directory as well as each known database/lock file.
// System aliases such as macOS /var -> /private/var remain usable.
void require_plain_path(const std::filesystem::path& path);

// Auth and storage keep a shared lease for their entire database lifetime.
// Maintenance takes an exclusive lease and fails immediately if either runs.
// The lock file is deliberately retained: unlinking it would split the lease.
class DataDirectoryLock {
public:
    explicit DataDirectoryLock(const std::filesystem::path& directory, bool exclusive = false);
    ~DataDirectoryLock();
    DataDirectoryLock(const DataDirectoryLock&) = delete;
    DataDirectoryLock& operator=(const DataDirectoryLock&) = delete;
private:
    struct State;
    std::unique_ptr<State> state_;
};
}
