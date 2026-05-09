// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <filesystem>
#include <fstream>
#include <vector>

/// A list of file paths that is stored in memory and on disk.
///
/// The only reason for this class to exist is recovery from crashes.
/// We need to be able to track every file that was successfully sent and saved,
/// and crashing mid transfer would make us potentially resend many files if
/// we only stored in them in RAM.
/// Using ClientStorage would be very inefficient if we were to mutate and save it
/// after every file.
///
/// During the file transfer, use this class to store and append each path in a simple
/// text file.
/// As soon as we finish the transfer, we go through the files we saved and save them to
/// the client storage.
/// After a crash, we first recover the list of files and save it to the client storage,
/// before trying the transfer again.
class FileListCache
{
public:
	FileListCache(const std::filesystem::path& storagePath) noexcept;

	void recordFile(const std::filesystem::path& newPath) noexcept;
	[[nodiscard]] std::vector<std::filesystem::path> consumeAllFiles() noexcept;

	[[nodiscard]] static std::vector<std::filesystem::path> recoverPreviouslyRecorded(const std::filesystem::path& storagePath) noexcept;
	static void removePreviouslyRecorded(const std::filesystem::path& storagePath) noexcept;

private:
	std::vector<std::filesystem::path> mFilePathList;
	std::basic_fstream<char> mStorageFile;
	std::filesystem::path mStoragePath;
};
