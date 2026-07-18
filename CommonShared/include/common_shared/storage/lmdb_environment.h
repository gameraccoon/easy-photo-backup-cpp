// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <filesystem>

#include "common_shared/storage/lmdb_return_codes.h"

struct MDB_env;

namespace Lmdb
{
	class Environment
	{
	public:
		[[nodiscard]] static Result<Environment> open(const std::filesystem::path& path, size_t maxNamedDatabases) noexcept;
		~Environment() noexcept;

		Environment(const Environment&) = delete;
		Environment& operator=(const Environment&) = delete;
		Environment(Environment&&) noexcept;
		Environment& operator=(Environment&&) noexcept;

		[[nodiscard]] Result<int> checkForStaleReaders() noexcept;

		[[nodiscard]] bool isValid() const noexcept { return mMdbEnvironment != nullptr; }
		[[nodiscard]] MDB_env* getRaw() noexcept { return mMdbEnvironment; };

	private:
		Environment(MDB_env* mdbEnvironment) noexcept;

	private:
		MDB_env* mMdbEnvironment;
	};
} // namespace Lmdb
