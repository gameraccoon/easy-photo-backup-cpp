// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <array>
#include <filesystem>

#include <gtest/gtest.h>

#include "common_shared/storage/lmdb_database.h"
#include "common_shared/storage/lmdb_environment.h"
#include "common_shared/storage/lmdb_transaction.h"

class LmdbTest : public testing::Test
{
protected:
	void SetUp() override
	{
		auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
		ASSERT_TRUE(env.isValid());

		auto transaction = Lmdb::ReadWriteTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());

		auto db = Lmdb::ReadWriteDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());

		ASSERT_EQ(transaction->commit(), Lmdb::ReturnCode::Success);
	}

	void TearDown() override
	{
		{
			auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
			ASSERT_TRUE(env.isValid());

			auto result = env->checkForStaleReaders();
			ASSERT_TRUE(result.isValid());
			EXPECT_EQ(0, *result);
		}

		std::filesystem::remove_all("test_lmdb_env_path");
	}
};

TEST_F(LmdbTest, Environment_Create_NoErrors)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	EXPECT_TRUE(env.isValid());
}

TEST_F(LmdbTest, Environment_CheckForStaleReaders_ReturnsZero)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());

	auto result = env->checkForStaleReaders();

	ASSERT_TRUE(result.isValid());
	EXPECT_EQ(0, *result);
}

TEST_F(LmdbTest, ReadTransaction_CreateAndAbandon_DoesNotCrashOrAssert)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());

	auto transaction = Lmdb::ReadOnlyTransaction::create(*env);
	EXPECT_TRUE(transaction.isValid());
}

TEST_F(LmdbTest, ReadTransaction_CreateAndAbort_DoesNotCrashOrAssert)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());

	auto transaction = Lmdb::ReadOnlyTransaction::create(*env);
	ASSERT_TRUE(transaction.isValid());
	transaction->abort();
}

TEST_F(LmdbTest, ReadWriteTransaction_CommitEmpty_ReturnsSuccess)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());
	auto transaction = Lmdb::ReadWriteTransaction::create(*env);
	ASSERT_TRUE(transaction.isValid());

	EXPECT_EQ(Lmdb::ReturnCode::Success, transaction->commit());
}

TEST_F(LmdbTest, ReadWriteTransaction_CreateAndAbort_DoesNotCrashOrAssert)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());
	auto transaction = Lmdb::ReadWriteTransaction::create(*env);
	ASSERT_TRUE(transaction.isValid());

	transaction->abort();
}

TEST_F(LmdbTest, ReadOnlyDatabase_OpenNonExistent_ReturnsNotFoundError)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());
	auto transaction = Lmdb::ReadOnlyTransaction::create(*env);
	ASSERT_TRUE(transaction.isValid());

	auto db = Lmdb::ReadOnlyDatabase::open(*transaction, "non_existent_db");

	ASSERT_TRUE(db.isError());
	ASSERT_EQ(Lmdb::ReturnCode::NotFound, db.getError());
}

TEST_F(LmdbTest, ReadWriteDatabase_OpenNonExisting_ReturnsSuccess)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());
	auto transaction = Lmdb::ReadWriteTransaction::create(*env);
	ASSERT_TRUE(transaction.isValid());

	auto db = Lmdb::ReadWriteDatabase::open(*transaction, "non_existent_db");

	ASSERT_TRUE(db.isValid());
}

TEST_F(LmdbTest, ReadOnlyDatabase_OpenSameDatabaseTwiceSequentially_BothOpenedSuccessfully)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());
	{
		auto transaction = Lmdb::ReadOnlyTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());
		auto db = Lmdb::ReadOnlyDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());
	}
	{
		auto transaction = Lmdb::ReadOnlyTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());
		auto db = Lmdb::ReadOnlyDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());
	}
}

TEST_F(LmdbTest, ReadWriteDatabase_OpenSameDatabaseTwiceSequentially_BothOpenedSuccessfully)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());
	{
		auto transaction = Lmdb::ReadWriteTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());
		auto db = Lmdb::ReadWriteDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());
	}
	{
		auto transaction = Lmdb::ReadWriteTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());
		auto db = Lmdb::ReadWriteDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());
	}
}

TEST_F(LmdbTest, Database_PutThenGet_ReturnsStoredValue)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());

	const std::string keyString = "key";
	const std::string valueString = "value";
	const auto key = std::as_bytes(std::span(keyString));
	const auto value = std::as_bytes(std::span(valueString));

	{
		auto transaction = Lmdb::ReadWriteTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());

		auto db = Lmdb::ReadWriteDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());

		EXPECT_EQ(Lmdb::ReturnCode::Success, db->putValue(key, value));
		EXPECT_EQ(Lmdb::ReturnCode::Success, transaction->commit());
	}

	{
		auto transaction = Lmdb::ReadOnlyTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());

		auto db = Lmdb::ReadOnlyDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());

		std::array<std::byte, 32> buffer{};
		size_t bytesRead = 0;

		EXPECT_EQ(Lmdb::ReturnCode::Success, db->getValue(key, buffer, bytesRead));

		EXPECT_EQ(5u, bytesRead);

		EXPECT_EQ(std::string(reinterpret_cast<char*>(buffer.data()), bytesRead), valueString);
	}
}

TEST_F(LmdbTest, Database_DeleteValue_RemovesKey)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());

	auto transaction = Lmdb::ReadWriteTransaction::create(*env);
	ASSERT_TRUE(transaction.isValid());

	auto db = Lmdb::ReadWriteDatabase::open(*transaction, "test_db");
	ASSERT_TRUE(db.isValid());

	const std::string keyString = "key";
	const std::string valueString = "value";
	const auto key = std::as_bytes(std::span(keyString));
	const auto value = std::as_bytes(std::span(valueString));

	EXPECT_EQ(Lmdb::ReturnCode::Success, db->putValue(key, value));

	EXPECT_EQ(Lmdb::ReturnCode::Success, db->deleteValue(key));

	std::array<std::byte, 32> buffer{};
	size_t bytesRead = 0;

	EXPECT_EQ(Lmdb::ReturnCode::NotFound, db->getValue(key, std::span(buffer), bytesRead));

	EXPECT_EQ(db->dropDatabase(), Lmdb::ReturnCode::Success);
}

TEST_F(LmdbTest, Database_EmptyDatabase_RemovesAllValues)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());

	auto transaction = Lmdb::ReadWriteTransaction::create(*env);
	ASSERT_TRUE(transaction.isValid());

	auto db = Lmdb::ReadWriteDatabase::open(*transaction, "test_db");
	ASSERT_TRUE(db.isValid());

	const std::string key1String = "key1";
	const std::string value1String = "value1";
	const std::string key2String = "key2";
	const std::string value2String = "value2";

	const auto key1 = std::as_bytes(std::span(key1String));
	const auto value1 = std::as_bytes(std::span(value1String));
	const auto key2 = std::as_bytes(std::span(key2String));
	const auto value2 = std::as_bytes(std::span(value2String));

	ASSERT_EQ(Lmdb::ReturnCode::Success, db->putValue(key1, value1));
	ASSERT_EQ(Lmdb::ReturnCode::Success, db->putValue(key2, value2));

	std::array<std::byte, 32> buffer{};
	size_t bytesRead = 0;

	ASSERT_EQ(Lmdb::ReturnCode::Success, db->getValue(key1, std::span(buffer), bytesRead));
	ASSERT_EQ(Lmdb::ReturnCode::Success, db->getValue(key2, std::span(buffer), bytesRead));

	EXPECT_EQ(Lmdb::ReturnCode::Success, db->emptyDatabase());

	EXPECT_EQ(Lmdb::ReturnCode::NotFound, db->getValue(key1, std::span(buffer), bytesRead));
	EXPECT_EQ(Lmdb::ReturnCode::NotFound, db->getValue(key2, std::span(buffer), bytesRead));
}

TEST_F(LmdbTest, Database_DropDatabase_RemovesDatabase)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());

	{
		auto transaction = Lmdb::ReadWriteTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());

		auto db = Lmdb::ReadWriteDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());

		EXPECT_EQ(Lmdb::ReturnCode::Success, db->dropDatabase());
		EXPECT_EQ(Lmdb::ReturnCode::Success, transaction->commit());
	}

	{
		auto transaction = Lmdb::ReadOnlyTransaction::create(*env);

		auto db = Lmdb::ReadOnlyDatabase::open(*transaction, "test_db");

		ASSERT_TRUE(db.isError());
		EXPECT_EQ(Lmdb::ReturnCode::NotFound, db.getError());
	}
}

TEST_F(LmdbTest, Transaction_Abort_DiscardsChanges)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());

	const std::string keyString = "key";
	const std::string valueString = "value";

	{
		auto transaction = Lmdb::ReadWriteTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());

		auto db = Lmdb::ReadWriteDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());

		ASSERT_EQ(Lmdb::ReturnCode::Success, db->putValue(std::as_bytes(std::span(keyString)), std::as_bytes(std::span(valueString))));

		transaction->abort();
	}

	{
		auto transaction = Lmdb::ReadOnlyTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());

		auto db = Lmdb::ReadOnlyDatabase::open(*transaction, "test_db");
		ASSERT_TRUE(db.isValid());

		std::array<std::byte, 32> buffer{};
		size_t bytesRead = 0;

		EXPECT_EQ(
			Lmdb::ReturnCode::NotFound,
			db->getValue(
				std::as_bytes(std::span(keyString)),
				buffer,
				bytesRead
			)
		);
	}
}

TEST_F(LmdbTest, Database_ReadValue_CallsCallbackWithStoredValue)
{
	auto env = Lmdb::Environment::open("test_lmdb_env_path", 10);
	ASSERT_TRUE(env.isValid());

	const std::string keyString = "key";
	const std::string valueString = "value";
	const auto key = std::as_bytes(std::span(keyString));
	const auto value = std::as_bytes(std::span(valueString));

	{
		auto transaction = Lmdb::ReadWriteTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());

		auto db = Lmdb::ReadWriteDatabase::open(*transaction, "db");
		ASSERT_TRUE(db.isValid());

		ASSERT_EQ(Lmdb::ReturnCode::Success, db->putValue(key, value));
		ASSERT_EQ(Lmdb::ReturnCode::Success, transaction->commit());
	}

	{
		auto transaction = Lmdb::ReadOnlyTransaction::create(*env);
		ASSERT_TRUE(transaction.isValid());

		auto db = Lmdb::ReadOnlyDatabase::open(*transaction, "db");
		ASSERT_TRUE(db.isValid());

		bool callbackCalled = false;
		std::string receivedValue;

		EXPECT_EQ(
			Lmdb::ReturnCode::Success,
			db->readValue(
				key,
				[&](std::span<const std::byte> bytes) {
					callbackCalled = true;

					receivedValue.assign(
						reinterpret_cast<const char*>(bytes.data()),
						bytes.size()
					);
				}
			)
		);

		EXPECT_TRUE(callbackCalled);
		EXPECT_EQ(valueString, receivedValue);
	}
}
