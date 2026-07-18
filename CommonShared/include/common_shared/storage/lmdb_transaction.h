// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/storage/lmdb_return_codes.h"

struct MDB_txn;

namespace Lmdb
{
	class Environment;
	class Transaction
	{
	public:
		~Transaction() noexcept;

		Transaction(const Transaction&) = delete;
		Transaction& operator=(const Transaction&) = delete;
		Transaction(Transaction&&) noexcept;
		Transaction& operator=(Transaction&&) noexcept;

		void abort() noexcept;

		[[nodiscard]] bool isValid() const noexcept { return mMdbTransaction != nullptr; }
		[[nodiscard]] MDB_txn* getRaw() noexcept { return mMdbTransaction; }

	protected:
		Transaction(MDB_txn* mdbTransaction) noexcept;

	protected:
		MDB_txn* mMdbTransaction;
	};

	class ReadWriteTransaction : public Transaction
	{
	public:
		static Result<ReadWriteTransaction> create(Environment& environment) noexcept;

		[[nodiscard]] ReturnCode commit() noexcept;

	private:
		ReadWriteTransaction(MDB_txn* mdbTransaction) noexcept;
	};

	class ReadOnlyTransaction : public Transaction
	{
	public:
		static Result<ReadOnlyTransaction> create(Environment& environment) noexcept;

	private:
		ReadOnlyTransaction(MDB_txn* mdbTransaction) noexcept;
	};
} // namespace Lmdb
