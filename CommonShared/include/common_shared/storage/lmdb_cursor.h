// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <span>

#include "common_shared/storage/lmdb_return_codes.h"

struct MDB_cursor;

namespace Lmdb
{
	struct CursorDataView
	{
		std::span<const std::byte> key;
		std::span<const std::byte> value;
	};

	class ReadOnlyTransaction;
	class ReadOnlyDatabase;
	class ReadOnlyCursor
	{
	public:
		~ReadOnlyCursor() noexcept;

		ReadOnlyCursor(const ReadOnlyCursor&) = delete;
		ReadOnlyCursor& operator=(const ReadOnlyCursor&) = delete;
		ReadOnlyCursor(ReadOnlyCursor&&) noexcept;
		ReadOnlyCursor& operator=(ReadOnlyCursor&&) noexcept;

		[[nodiscard]] static Result<ReadOnlyCursor> open(ReadOnlyTransaction& transaction, ReadOnlyDatabase& database) noexcept;

		[[nodiscard]] ReturnCode first() noexcept;
		[[nodiscard]] ReturnCode next() noexcept;

		[[nodiscard]] Result<CursorDataView> get() noexcept;

	private:
		ReadOnlyCursor(MDB_cursor* mdbCursor) noexcept;

	private:
		MDB_cursor* mMdbCursor;
	};
} // namespace Lmdb
