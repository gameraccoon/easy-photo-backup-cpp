// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/file_list_cache.h"

#include "common_shared/debug/log.h"

FileListCache::FileListCache(const std::filesystem::path& storagePath) noexcept
	: mStoragePath(storagePath)
{
}

void FileListCache::recordFile(const std::filesystem::path& newPath) noexcept
{
	mFilePathList.push_back(newPath);
	try
	{
		if (!mStorageFile.is_open())
		{
			mStorageFile.open(mStoragePath, std::ios_base::out | std::ios_base::app);
		}

		if constexpr (std::is_same_v<std::filesystem::path::value_type, std::fstream::char_type>)
		{
			mStorageFile.write(newPath.native().c_str(), newPath.native().size());
		}
		else
		{
			const std::string pathStr = newPath.string();
			mStorageFile.write(pathStr.c_str(), pathStr.size());
		}
	}
	catch (...)
	{
		Debug::Log::printDebug("Could not write to file list cache file {}", mStoragePath.generic_string());
	}
}

std::vector<std::filesystem::path> FileListCache::consumeAllFiles() noexcept
{
	try
	{
		if (mStorageFile.is_open())
		{
			mStorageFile.close();
		}
		std::filesystem::remove(mStoragePath);
	}
	catch (...)
	{
		Debug::Log::printDebug("Could not close or remove file list cache file {}", mStoragePath.generic_string());
	}

	return std::move(mFilePathList);
}

std::vector<std::filesystem::path> FileListCache::recoverPreviouslyRecorded(const std::filesystem::path& storagePath) noexcept
{
	std::vector<std::filesystem::path> result;
	if (std::filesystem::exists(storagePath) && !std::filesystem::is_directory(storagePath))
	{
		try
		{
			std::ifstream file{ storagePath };
			for (std::string line; getline(file, line);)
			{
				result.emplace_back(line);
			}
		}
		catch (...)
		{
			Debug::Log::printDebug("Could not read file list cache file {}", storagePath.generic_string());
		}
	}

	return result;
}

void FileListCache::removePreviouslyRecorded(const std::filesystem::path& storagePath) noexcept
{
	std::filesystem::remove(storagePath);
}
