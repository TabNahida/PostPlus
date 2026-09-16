#include <postplus/data_lock.hpp>
#include <stdexcept>
#include <system_error>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace postplus {
namespace fs = std::filesystem;
void require_plain_path(const fs::path& path) {
    auto current = fs::absolute(path).lexically_normal();
    while (current != current.root_path() && current.filename().empty()) current = current.parent_path();
#ifdef _WIN32
    const auto attributes = GetFileAttributesW(current.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const auto error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return;
        throw std::runtime_error("cannot inspect data path: " + current.string());
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
        throw std::runtime_error("refusing linked or reparse-point data path: " + current.string());
#else
    std::error_code error;
    const auto status = fs::symlink_status(current, error);
    if (error && error != std::errc::no_such_file_or_directory)
        throw std::runtime_error("cannot inspect data path: " + current.string());
    if (fs::is_symlink(status)) throw std::runtime_error("refusing symbolic-link data path: " + current.string());
#endif
}
struct DataDirectoryLock::State {
#ifdef _WIN32
    HANDLE file = INVALID_HANDLE_VALUE;
    OVERLAPPED overlap{};
    ~State() {
        if (file != INVALID_HANDLE_VALUE) { UnlockFileEx(file, 0, 1, 0, &overlap); CloseHandle(file); }
    }
#else
    int file = -1;
    ~State() { if (file >= 0) { flock(file, LOCK_UN); close(file); } }
#endif
};
DataDirectoryLock::DataDirectoryLock(const fs::path& directory, bool exclusive) : state_(std::make_unique<State>()) {
    require_plain_path(directory);
    if (!fs::is_directory(directory)) throw std::runtime_error("data directory does not exist: " + directory.string());
    const auto path = fs::absolute(directory / ".postplus-data.lock").lexically_normal();
    require_plain_path(path);
#ifdef _WIN32
    state_->file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (state_->file == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open data directory lock");
    BY_HANDLE_FILE_INFORMATION details{};
    if (!GetFileInformationByHandle(state_->file, &details) || (details.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        (details.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || details.nNumberOfLinks != 1)
        throw std::runtime_error("data directory lock must be a regular file with one link");
    const auto flags = LOCKFILE_FAIL_IMMEDIATELY | (exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0);
    if (!LockFileEx(state_->file, flags, 0, 1, 0, &state_->overlap))
        throw std::runtime_error(exclusive ? "data is in use; stop all PostPlus services before cleanup" : "data maintenance is active; try starting PostPlus again later");
#else
    state_->file = open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (state_->file < 0) throw std::runtime_error("cannot open data directory lock");
    struct stat details{};
    if (fstat(state_->file, &details) != 0 || !S_ISREG(details.st_mode) || details.st_nlink != 1)
        throw std::runtime_error("data directory lock must be a regular file with one link");
    if (flock(state_->file, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0)
        throw std::runtime_error(exclusive ? "data is in use; stop all PostPlus services before cleanup" : "data maintenance is active; try starting PostPlus again later");
#endif
}
DataDirectoryLock::~DataDirectoryLock() = default;
}
