// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/storage/lmdb_environment.h"

#include <liblmdb/lmdb.h>

#include "common_shared/debug/assert.h"

namespace Lmdb
{
	Environment::Environment(MDB_env* mdbEnvironment) noexcept
		: mMdbEnvironment(mdbEnvironment)
	{
	}

	Environment::Environment(Environment&& other) noexcept
		: Environment(other.mMdbEnvironment)
	{
		other.mMdbEnvironment = nullptr;
	}

	Environment::~Environment() noexcept
	{
		if (mMdbEnvironment != nullptr)
		{
			const int returnCode = mdb_env_sync(mMdbEnvironment, 1);
			if (returnCode != 0)
			{
				reportDebugError("Could not flush LMDB environment before closing: '{}'", mdb_strerror(returnCode));
			}
			mdb_env_close(mMdbEnvironment);
		}
	}

	Environment& Environment::operator=(Environment&& other) noexcept
	{
		mMdbEnvironment = other.mMdbEnvironment;
		other.mMdbEnvironment = nullptr;
		return *this;
	}

	Result<Environment> Environment::open(const std::filesystem::path& path, size_t maxNamedDatabases) noexcept
	{
		MDB_env* mdbEnvironment;
		int returnCode = mdb_env_create(&mdbEnvironment);
		if (returnCode != 0)
		{
			reportDebugError("Could not create LMDB environment: '{}'", mdb_strerror(returnCode));
			return parseReturnCode(returnCode);
		}

		// 1Gb, if the database ever wants to grow bigger, we definitely have a problem
		returnCode = mdb_env_set_mapsize(mdbEnvironment, 1 * 1024 * 1024 * 1024);
		if (returnCode != 0)
		{
			reportDebugError("Could not size LMDB environment: '{}'", mdb_strerror(returnCode));
			return parseReturnCode(returnCode);
		}

		returnCode = mdb_env_set_maxdbs(mdbEnvironment, maxNamedDatabases);
		if (returnCode != 0)
		{
			reportDebugError("Could not set max number ({}) of named databases in LMDB environment: '{}'", maxNamedDatabases, mdb_strerror(returnCode));
			return parseReturnCode(returnCode);
		}

		try
		{
			std::filesystem::create_directory(path);
		}
		catch (const std::exception& e)
		{
			reportDebugError("Could not create LMDB environment directory '{}': '{}'", path.string(), e.what());
			return ReturnCode::CanNotCreateDirectory;
		}
		catch (...)
		{
			reportDebugError("Could not create LMDB environment directory '{}'", path.string());
			return ReturnCode::CanNotCreateDirectory;
		}

		returnCode = mdb_env_open(mdbEnvironment, path.c_str(), 0, 0644);
		if (returnCode != 0)
		{
			reportDebugError("Could not open LMDB environment: '{}'", mdb_strerror(returnCode));
			return parseReturnCode(returnCode);
		}

		return Environment(mdbEnvironment);
	}

	Result<int> Environment::checkForStaleReaders() noexcept
	{
		if (mMdbEnvironment == nullptr)
		{
			reportDebugError("Tried to perform stale reader check on non-initialized LMDB environment");
			return ReturnCode::LogicalError;
		}

		int result = 0;
		const int returnCode = mdb_reader_check(mMdbEnvironment, &result);
		if (returnCode != 0)
		{
			reportDebugError("Could not perform stale reader check on LMDB environment: '{}'", mdb_strerror(returnCode));
			return parseReturnCode(returnCode);
		}
		return result;
	}
} // namespace Lmdb
