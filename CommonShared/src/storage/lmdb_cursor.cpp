// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/storage/lmdb_cursor.h"

#include <liblmdb/lmdb.h>

#include "common_shared/debug/assert.h"
#include "common_shared/storage/lmdb_database.h"
#include "common_shared/storage/lmdb_transaction.h"

namespace Lmdb
{
	ReadOnlyCursor::ReadOnlyCursor(MDB_cursor* mdbCursor) noexcept
		: mMdbCursor(mdbCursor)
	{}

	ReadOnlyCursor::~ReadOnlyCursor() noexcept
	{
		if (mMdbCursor != nullptr)
		{
			mdb_cursor_close(mMdbCursor);
		}
	}

	ReadOnlyCursor::ReadOnlyCursor(ReadOnlyCursor&& other) noexcept
		: ReadOnlyCursor(other.mMdbCursor)
	{
		other.mMdbCursor = nullptr;
	}

	ReadOnlyCursor& ReadOnlyCursor::operator=(ReadOnlyCursor&& other) noexcept
	{
		mMdbCursor = other.mMdbCursor;
		other.mMdbCursor = nullptr;
		return *this;
	}

	Result<ReadOnlyCursor> ReadOnlyCursor::open(ReadOnlyTransaction& transaction, ReadOnlyDatabase& database) noexcept
	{
		MDB_cursor* mdbCursor;
		int returnCode = mdb_cursor_open(transaction.getRaw(), database.getRaw(), &mdbCursor);
		if (returnCode != 0)
		{
			reportDebugError("Could not create LMDB cursor: '{}'", mdb_strerror(returnCode));
			return parseReturnCode(returnCode);
		}

		return ReadOnlyCursor(mdbCursor);
	}

	ReturnCode ReadOnlyCursor::first() noexcept
	{
		MDB_val key{};
		MDB_val value{};
		int returnCode = mdb_cursor_get(mMdbCursor, &key, &value, MDB_FIRST);
		assertRelease(returnCode == 0 || returnCode == MDB_NOTFOUND, "Could not move LMDB cursor to first element: '{}'", mdb_strerror(returnCode));
		return parseReturnCode(returnCode);
	}

	ReturnCode ReadOnlyCursor::next() noexcept
	{
		MDB_val key{};
		MDB_val value{};
		int returnCode = mdb_cursor_get(mMdbCursor, &key, &value, MDB_NEXT);
		assertRelease(returnCode == 0 || returnCode == MDB_NOTFOUND, "Could not move LMDB cursor to the next position: '{}'", mdb_strerror(returnCode));
		return parseReturnCode(returnCode);
	}

	Result<CursorDataView> ReadOnlyCursor::get() noexcept
	{
		MDB_val key{};
		MDB_val value{};
		int returnCode = mdb_cursor_get(mMdbCursor, &key, &value, MDB_GET_CURRENT);
		if (returnCode != 0)
		{
			reportDebugError("Could not get data from LMDB cursor: '{}'", mdb_strerror(returnCode));
			return parseReturnCode(returnCode);
		}
		return CursorDataView{
			.key = std::span<const std::byte>(static_cast<const std::byte*>(key.mv_data), key.mv_size),
			.value = std::span<const std::byte>(static_cast<const std::byte*>(value.mv_data), value.mv_size),
		};
	}
} // namespace Lmdb
