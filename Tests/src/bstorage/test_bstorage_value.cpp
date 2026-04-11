// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <streambuf>

#include <gtest/gtest.h>

#include "common_shared/bstorage/value.h"

TEST(BStorageValue, u8_test)
{
	BStorage::Value v = BStorage::Value::makeU8(3);

	ASSERT_TRUE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	ASSERT_NE(v.asU8(), nullptr);
	EXPECT_EQ(*v.asU8(), static_cast<uint8_t>(3));
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, u8_const_test)
{
	const BStorage::Value v = BStorage::Value::makeU8(3);

	ASSERT_TRUE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	ASSERT_NE(v.asU8(), nullptr);
	EXPECT_EQ(*v.asU8(), static_cast<uint8_t>(3));
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, u8_copy_test)
{
	BStorage::Value v1 = BStorage::Value::makeU8(4);

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::U8));
	ASSERT_NE(v1.asU8(), nullptr);
	EXPECT_EQ(*v1.asU8(), static_cast<uint8_t>(4));
	ASSERT_TRUE(v2.isA(BStorage::Tag::U8));
	ASSERT_NE(v2.asU8(), nullptr);
	EXPECT_EQ(*v2.asU8(), static_cast<uint8_t>(4));
}

TEST(BStorageValue, u8_move_test)
{
	BStorage::Value v1 = BStorage::Value::makeU8(4);

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::U8));
	ASSERT_NE(v2.asU8(), nullptr);
	EXPECT_EQ(*v2.asU8(), static_cast<uint8_t>(4));
}

TEST(BStorageValue, u16_test)
{
	BStorage::Value v = BStorage::Value::makeU16(1000);

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	ASSERT_TRUE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	ASSERT_NE(v.asU16(), nullptr);
	EXPECT_EQ(*v.asU16(), static_cast<uint16_t>(1000));
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, u16_const_test)
{
	const BStorage::Value v = BStorage::Value::makeU16(1000);

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	ASSERT_TRUE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	ASSERT_NE(v.asU16(), nullptr);
	EXPECT_EQ(*v.asU16(), static_cast<uint16_t>(1000));
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, u16_copy_test)
{
	BStorage::Value v1 = BStorage::Value::makeU16(1000);

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::U16));
	ASSERT_NE(v1.asU16(), nullptr);
	EXPECT_EQ(*v1.asU16(), static_cast<uint16_t>(1000));
	ASSERT_TRUE(v2.isA(BStorage::Tag::U16));
	ASSERT_NE(v2.asU16(), nullptr);
	EXPECT_EQ(*v2.asU16(), static_cast<uint16_t>(1000));
}

TEST(BStorageValue, u16_move_test)
{
	BStorage::Value v1 = BStorage::Value::makeU16(1000);

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::U16));
	ASSERT_NE(v2.asU16(), nullptr);
	EXPECT_EQ(*v2.asU16(), static_cast<uint16_t>(1000));
}

TEST(BStorageValue, u32_test)
{
	BStorage::Value v = BStorage::Value::makeU32(100000);

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	ASSERT_TRUE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	ASSERT_NE(v.asU32(), nullptr);
	EXPECT_EQ(*v.asU32(), static_cast<uint32_t>(100000));
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, u32_const_test)
{
	const BStorage::Value v = BStorage::Value::makeU32(100000);

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	ASSERT_TRUE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	ASSERT_NE(v.asU32(), nullptr);
	EXPECT_EQ(*v.asU32(), static_cast<uint32_t>(100000));
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, u32_copy_test)
{
	BStorage::Value v1 = BStorage::Value::makeU32(100000);

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::U32));
	ASSERT_NE(v1.asU32(), nullptr);
	EXPECT_EQ(*v1.asU32(), static_cast<uint32_t>(100000));
	ASSERT_TRUE(v2.isA(BStorage::Tag::U32));
	ASSERT_NE(v2.asU32(), nullptr);
	EXPECT_EQ(*v2.asU32(), static_cast<uint32_t>(100000));
}

TEST(BStorageValue, u32_move_test)
{
	BStorage::Value v1 = BStorage::Value::makeU32(100000);

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::U32));
	ASSERT_NE(v2.asU32(), nullptr);
	EXPECT_EQ(*v2.asU32(), static_cast<uint32_t>(100000));
}

TEST(BStorageValue, u64_test)
{
	BStorage::Value v = BStorage::Value::makeU64(9999999999ULL);

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	ASSERT_TRUE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	ASSERT_NE(v.asU64(), nullptr);
	EXPECT_EQ(*v.asU64(), static_cast<uint64_t>(9999999999ULL));
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, u64_const_test)
{
	const BStorage::Value v = BStorage::Value::makeU64(9999999999ULL);

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	ASSERT_TRUE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	ASSERT_NE(v.asU64(), nullptr);
	EXPECT_EQ(*v.asU64(), static_cast<uint64_t>(9999999999ULL));
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, u64_copy_test)
{
	BStorage::Value v1 = BStorage::Value::makeU64(9999999999ULL);

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::U64));
	ASSERT_NE(v1.asU64(), nullptr);
	EXPECT_EQ(*v1.asU64(), static_cast<uint64_t>(9999999999ULL));
	ASSERT_TRUE(v2.isA(BStorage::Tag::U64));
	ASSERT_NE(v2.asU64(), nullptr);
	EXPECT_EQ(*v2.asU64(), static_cast<uint64_t>(9999999999ULL));
}

TEST(BStorageValue, u64_move_test)
{
	BStorage::Value v1 = BStorage::Value::makeU64(9999999999ULL);

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::U64));
	ASSERT_NE(v2.asU64(), nullptr);
	EXPECT_EQ(*v2.asU64(), static_cast<uint64_t>(9999999999ULL));
}

TEST(BStorageValue, string_test)
{
	BStorage::Value v = BStorage::Value::makeString(std::string("hello"));

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	ASSERT_TRUE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	ASSERT_NE(v.asString(), nullptr);
	EXPECT_EQ(*v.asString(), "hello");
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, string_const_test)
{
	const BStorage::Value v = BStorage::Value::makeString(std::string("hello"));

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	ASSERT_TRUE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	ASSERT_NE(v.asString(), nullptr);
	EXPECT_EQ(*v.asString(), "hello");
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, string_move_construct_test)
{
	std::string s = "world";

	BStorage::Value v = BStorage::Value::makeString(std::move(s));

	ASSERT_TRUE(v.isA(BStorage::Tag::String));
	ASSERT_NE(v.asString(), nullptr);
	EXPECT_EQ(*v.asString(), "world");
}

TEST(BStorageValue, string_copy_test)
{
	BStorage::Value v1 = BStorage::Value::makeString(std::string("hello"));

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::String));
	ASSERT_NE(v1.asString(), nullptr);
	EXPECT_EQ(*v1.asString(), "hello");
	ASSERT_TRUE(v2.isA(BStorage::Tag::String));
	ASSERT_NE(v2.asString(), nullptr);
	EXPECT_EQ(*v2.asString(), "hello");
}

TEST(BStorageValue, string_move_test)
{
	BStorage::Value v1 = BStorage::Value::makeString(std::string("hello"));

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::String));
	ASSERT_NE(v2.asString(), nullptr);
	EXPECT_EQ(*v2.asString(), "hello");
}

TEST(BStorageValue, bytearray_test)
{
	const std::vector<std::byte> bytes = { std::byte(0x01), std::byte(0x02), std::byte(0x03) };

	BStorage::Value v = BStorage::Value::makeByteArray(bytes);

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	ASSERT_TRUE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	ASSERT_NE(v.asByteArray(), nullptr);
	EXPECT_EQ(*v.asByteArray(), bytes);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, bytearray_const_test)
{
	const std::vector<std::byte> bytes = { std::byte(0x01), std::byte(0x02), std::byte(0x03) };

	const BStorage::Value v = BStorage::Value::makeByteArray(bytes);

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	ASSERT_TRUE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	ASSERT_NE(v.asByteArray(), nullptr);
	EXPECT_EQ(*v.asByteArray(), bytes);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, bytearray_move_construct_test)
{
	std::vector<std::byte> bytes = { std::byte(0xAA), std::byte(0xBB), std::byte(0xCC) };

	BStorage::Value v = BStorage::Value::makeByteArray(std::move(bytes));

	ASSERT_TRUE(v.isA(BStorage::Tag::ByteArray));
	ASSERT_NE(v.asByteArray(), nullptr);
	EXPECT_EQ((*v.asByteArray()), (std::vector<std::byte>{ std::byte(0xAA), std::byte(0xBB), std::byte(0xCC) }));
}

TEST(BStorageValue, bytearray_copy_test)
{
	const std::vector<std::byte> bytes = { std::byte(0x01), std::byte(0x02), std::byte(0x03) };
	BStorage::Value v1 = BStorage::Value::makeByteArray(bytes);

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::ByteArray));
	ASSERT_NE(v1.asByteArray(), nullptr);
	EXPECT_EQ(*v1.asByteArray(), bytes);
	ASSERT_TRUE(v2.isA(BStorage::Tag::ByteArray));
	ASSERT_NE(v2.asByteArray(), nullptr);
	EXPECT_EQ(*v2.asByteArray(), bytes);
}

TEST(BStorageValue, bytearray_move_test)
{
	const std::vector<std::byte> bytes = { std::byte(0x01), std::byte(0x02), std::byte(0x03) };
	BStorage::Value v1 = BStorage::Value::makeByteArray(bytes);

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::ByteArray));
	ASSERT_NE(v2.asByteArray(), nullptr);
	EXPECT_EQ(*v2.asByteArray(), bytes);
}

TEST(BStorageValue, option_test)
{
	auto inner = std::make_unique<BStorage::Value>(BStorage::Value::makeU32(42));

	BStorage::Value v = BStorage::Value::makeOption(std::move(inner));

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	ASSERT_TRUE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	ASSERT_NE(v.asOption(), nullptr);
	ASSERT_NE(v.asOption()->get(), nullptr);
	EXPECT_TRUE((*v.asOption())->isA(BStorage::Tag::U32));
	ASSERT_NE((*v.asOption())->asU32(), nullptr);
	EXPECT_EQ(*(*v.asOption())->asU32(), static_cast<uint32_t>(42));
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, option_const_test)
{
	auto inner = std::make_unique<BStorage::Value>(BStorage::Value::makeU32(42));

	const BStorage::Value v = BStorage::Value::makeOption(std::move(inner));

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	ASSERT_TRUE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	ASSERT_NE(v.asOption(), nullptr);
	ASSERT_NE(v.asOption()->get(), nullptr);
	EXPECT_TRUE((*v.asOption())->isA(BStorage::Tag::U32));
	ASSERT_NE((*v.asOption())->asU32(), nullptr);
	EXPECT_EQ(*(*v.asOption())->asU32(), static_cast<uint32_t>(42));
	EXPECT_EQ(v.asArray(), nullptr);
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, option_null_test)
{
	BStorage::Value v = BStorage::Value::makeOption(nullptr);

	ASSERT_TRUE(v.isA(BStorage::Tag::Option));
	ASSERT_NE(v.asOption(), nullptr);
	EXPECT_EQ(v.asOption()->get(), nullptr);
}

TEST(BStorageValue, option_copy_test)
{
	auto inner = std::make_unique<BStorage::Value>(BStorage::Value::makeU32(42));
	BStorage::Value v1 = BStorage::Value::makeOption(std::move(inner));

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::Option));
	ASSERT_NE(v1.asOption(), nullptr);
	ASSERT_NE(v1.asOption()->get(), nullptr);
	EXPECT_EQ(*(*v1.asOption())->asU32(), static_cast<uint32_t>(42));
	ASSERT_TRUE(v2.isA(BStorage::Tag::Option));
	ASSERT_NE(v2.asOption(), nullptr);
	ASSERT_NE(v2.asOption()->get(), nullptr);
	EXPECT_EQ(*(*v2.asOption())->asU32(), static_cast<uint32_t>(42));
	// Confirm deep copy – pointers must differ
	EXPECT_NE(v1.asOption()->get(), v2.asOption()->get());
}

TEST(BStorageValue, option_copy_test_null)
{
	BStorage::Value v1 = BStorage::Value::makeOption(nullptr);

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::Option));
	ASSERT_NE(v1.asOption(), nullptr);
	EXPECT_EQ(v1.asOption()->get(), nullptr);
	ASSERT_TRUE(v2.isA(BStorage::Tag::Option));
	ASSERT_NE(v2.asOption(), nullptr);
	EXPECT_EQ(v2.asOption()->get(), nullptr);
}

TEST(BStorageValue, option_move_test)
{
	auto inner = std::make_unique<BStorage::Value>(BStorage::Value::makeU32(42));
	BStorage::Value v1 = BStorage::Value::makeOption(std::move(inner));

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::Option));
	ASSERT_NE(v2.asOption(), nullptr);
	ASSERT_NE(v2.asOption()->get(), nullptr);
	EXPECT_EQ(*(*v2.asOption())->asU32(), static_cast<uint32_t>(42));
}

TEST(BStorageValue, option_move_test_null)
{
	BStorage::Value v1 = BStorage::Value::makeOption(nullptr);

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::Option));
	ASSERT_NE(v2.asOption(), nullptr);
	EXPECT_EQ(v2.asOption()->get(), nullptr);
}

TEST(BStorageValue, array_test)
{
	std::vector<BStorage::Value> elems;
	elems.push_back(BStorage::Value::makeU8(1));
	elems.push_back(BStorage::Value::makeU8(2));

	BStorage::Value v = BStorage::Value::makeArray(std::move(elems));

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	ASSERT_TRUE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	ASSERT_NE(v.asArray(), nullptr);
	ASSERT_EQ(v.asArray()->size(), 2u);
	EXPECT_TRUE((*v.asArray())[0].isA(BStorage::Tag::U8));
	EXPECT_EQ(*(*v.asArray())[0].asU8(), static_cast<uint8_t>(1));
	EXPECT_TRUE((*v.asArray())[1].isA(BStorage::Tag::U8));
	EXPECT_EQ(*(*v.asArray())[1].asU8(), static_cast<uint8_t>(2));
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, array_const_test)
{
	std::vector<BStorage::Value> elems;
	elems.push_back(BStorage::Value::makeU8(1));
	elems.push_back(BStorage::Value::makeU8(2));

	const BStorage::Value v = BStorage::Value::makeArray(std::move(elems));

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	ASSERT_TRUE(v.isA(BStorage::Tag::Array));
	EXPECT_FALSE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	ASSERT_NE(v.asArray(), nullptr);
	ASSERT_EQ(v.asArray()->size(), 2u);
	EXPECT_EQ(*(*v.asArray())[0].asU8(), static_cast<uint8_t>(1));
	EXPECT_EQ(*(*v.asArray())[1].asU8(), static_cast<uint8_t>(2));
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, array_different_types)
{
	std::vector<BStorage::Value> elems;
	elems.push_back(BStorage::Value::makeU8(1));
	elems.push_back(BStorage::Value::makeU16(2000));

	BStorage::Value v = BStorage::Value::makeArray(std::move(elems));

	ASSERT_TRUE(v.isA(BStorage::Tag::Array));
	ASSERT_EQ(v.asArray()->size(), 2u);
	EXPECT_TRUE((*v.asArray())[0].isA(BStorage::Tag::U8));
	EXPECT_EQ(*(*v.asArray())[0].asU8(), static_cast<uint8_t>(1));
	EXPECT_TRUE((*v.asArray())[1].isA(BStorage::Tag::U16));
	EXPECT_EQ(*(*v.asArray())[1].asU16(), static_cast<uint16_t>(2000));
	EXPECT_EQ(v.asObject(), nullptr);
}

TEST(BStorageValue, array_lvalue_construct_test)
{
	std::vector<BStorage::Value> elems;
	elems.push_back(BStorage::Value::makeU16(7));

	BStorage::Value v = BStorage::Value::makeArray(elems); // lvalue overload

	ASSERT_TRUE(v.isA(BStorage::Tag::Array));
	ASSERT_NE(v.asArray(), nullptr);
	ASSERT_EQ(v.asArray()->size(), 1u);
	EXPECT_EQ(*(*v.asArray())[0].asU16(), static_cast<uint16_t>(7));
}

TEST(BStorageValue, array_empty_test)
{
	BStorage::Value v = BStorage::Value::makeArray(std::vector<BStorage::Value>{});

	ASSERT_TRUE(v.isA(BStorage::Tag::Array));
	ASSERT_NE(v.asArray(), nullptr);
	EXPECT_TRUE(v.asArray()->empty());
}

TEST(BStorageValue, array_copy_test)
{
	std::vector<BStorage::Value> elems;
	elems.push_back(BStorage::Value::makeU8(5));
	BStorage::Value v1 = BStorage::Value::makeArray(std::move(elems));

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::Array));
	ASSERT_NE(v1.asArray(), nullptr);
	EXPECT_EQ(v1.asArray()->size(), 1u);
	ASSERT_TRUE(v2.isA(BStorage::Tag::Array));
	ASSERT_NE(v2.asArray(), nullptr);
	EXPECT_EQ(v2.asArray()->size(), 1u);
	EXPECT_EQ(*(*v2.asArray())[0].asU8(), static_cast<uint8_t>(5));
}

TEST(BStorageValue, array_move_test)
{
	std::vector<BStorage::Value> elems;
	elems.push_back(BStorage::Value::makeU8(5));
	BStorage::Value v1 = BStorage::Value::makeArray(std::move(elems));

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::Array));
	ASSERT_NE(v2.asArray(), nullptr);
	EXPECT_EQ(v2.asArray()->size(), 1u);
	EXPECT_EQ(*(*v2.asArray())[0].asU8(), static_cast<uint8_t>(5));
}

TEST(BStorageValue, object_test)
{
	std::unordered_map<std::string, BStorage::Value> map;
	map.emplace("key", BStorage::Value::makeU64(77));

	BStorage::Value v = BStorage::Value::makeObject(std::move(map));

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	ASSERT_TRUE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	ASSERT_NE(v.asObject(), nullptr);
	ASSERT_EQ(v.asObject()->size(), 1u);
	ASSERT_NE(v.asObject()->find("key"), v.asObject()->end());
	EXPECT_EQ(*v.asObject()->at("key").asU64(), static_cast<uint64_t>(77));
}

TEST(BStorageValue, object_const_test)
{
	std::unordered_map<std::string, BStorage::Value> map;
	map.emplace("key", BStorage::Value::makeU64(77));

	const BStorage::Value v = BStorage::Value::makeObject(std::move(map));

	EXPECT_FALSE(v.isA(BStorage::Tag::U8));
	EXPECT_FALSE(v.isA(BStorage::Tag::U16));
	EXPECT_FALSE(v.isA(BStorage::Tag::U32));
	EXPECT_FALSE(v.isA(BStorage::Tag::U64));
	EXPECT_FALSE(v.isA(BStorage::Tag::String));
	EXPECT_FALSE(v.isA(BStorage::Tag::ByteArray));
	EXPECT_FALSE(v.isA(BStorage::Tag::Option));
	EXPECT_FALSE(v.isA(BStorage::Tag::Array));
	ASSERT_TRUE(v.isA(BStorage::Tag::Object));
	EXPECT_EQ(v.asU8(), nullptr);
	EXPECT_EQ(v.asU16(), nullptr);
	EXPECT_EQ(v.asU32(), nullptr);
	EXPECT_EQ(v.asU64(), nullptr);
	EXPECT_EQ(v.asString(), nullptr);
	EXPECT_EQ(v.asByteArray(), nullptr);
	EXPECT_EQ(v.asOption(), nullptr);
	EXPECT_EQ(v.asArray(), nullptr);
	ASSERT_NE(v.asObject(), nullptr);
	ASSERT_EQ(v.asObject()->size(), 1u);
	ASSERT_NE(v.asObject()->find("key"), v.asObject()->end());
	EXPECT_EQ(*v.asObject()->at("key").asU64(), static_cast<uint64_t>(77));
}
TEST(BStorageValue, object_lvalue_construct_test)
{
	std::unordered_map<std::string, BStorage::Value> map;
	map.emplace("x", BStorage::Value::makeString(std::string("val")));

	BStorage::Value v = BStorage::Value::makeObject(map); // lvalue overload

	ASSERT_TRUE(v.isA(BStorage::Tag::Object));
	ASSERT_NE(v.asObject(), nullptr);
	EXPECT_EQ(*v.asObject()->at("x").asString(), "val");
}

TEST(BStorageValue, object_empty_test)
{
	BStorage::Value v = BStorage::Value::makeObject(std::unordered_map<std::string, BStorage::Value>{});

	ASSERT_TRUE(v.isA(BStorage::Tag::Object));
	ASSERT_NE(v.asObject(), nullptr);
	EXPECT_TRUE(v.asObject()->empty());
}

TEST(BStorageValue, object_copy_test)
{
	std::unordered_map<std::string, BStorage::Value> map;
	map.emplace("k", BStorage::Value::makeU8(9));
	BStorage::Value v1 = BStorage::Value::makeObject(std::move(map));

	BStorage::Value v2(v1);

	ASSERT_TRUE(v1.isA(BStorage::Tag::Object));
	ASSERT_NE(v1.asObject(), nullptr);
	EXPECT_EQ(v1.asObject()->size(), 1u);
	ASSERT_TRUE(v2.isA(BStorage::Tag::Object));
	ASSERT_NE(v2.asObject(), nullptr);
	EXPECT_EQ(v2.asObject()->size(), 1u);
	EXPECT_EQ(*v2.asObject()->at("k").asU8(), static_cast<uint8_t>(9));
}

TEST(BStorageValue, object_move_test)
{
	std::unordered_map<std::string, BStorage::Value> map;
	map.emplace("k", BStorage::Value::makeU8(9));
	BStorage::Value v1 = BStorage::Value::makeObject(std::move(map));

	BStorage::Value v2(std::move(v1));

	ASSERT_TRUE(v2.isA(BStorage::Tag::Object));
	ASSERT_NE(v2.asObject(), nullptr);
	EXPECT_EQ(v2.asObject()->size(), 1u);
	EXPECT_EQ(*v2.asObject()->at("k").asU8(), static_cast<uint8_t>(9));
}

class VecStreamBuf : public std::streambuf
{
public:
	explicit VecStreamBuf(std::vector<char>& vec)
	{
		setp(vec.data(), vec.data() + vec.size());
		setg(vec.data(), vec.data(), vec.data() + vec.size());
	}

	// How many bytes were actually written?
	std::size_t bytes_written() const noexcept
	{
		return pptr() - pbase();
	}
};

TEST(BStorageValue, serialization_test)
{
	const BStorage::Value initial = BStorage::Value::makeObject({
		{
			"k1",
			BStorage::Value::makeArray({
				{
					BStorage::Value::makeByteArray(std::vector<std::byte>({ std::byte(0x10), std::byte(0x20), std::byte(0x30) })),
					BStorage::Value::makeU16(0x4567),
					BStorage::Value::makeOption(nullptr),
					BStorage::Value::makeOption(std::make_unique<BStorage::Value>(BStorage::Value::makeString("test"))),
				},
			}),
		},
		{
			"k2",
			BStorage::Value::makeArray({
				{
					BStorage::Value::makeU16(0x6789),
					BStorage::Value::makeU16(0x1234),
				},
			}),
		},
		{
			"k3",
			BStorage::Value::makeArray({
				{
					BStorage::Value::makeOption(nullptr),
					BStorage::Value::makeOption(std::make_unique<BStorage::Value>(BStorage::Value::makeU8(0xFF))),
				},
			}),
		},
		{
			"k4",
			BStorage::Value::makeArray({}),
		},
	});

	const BStorage::Value expected = BStorage::Value::makeObject({
		{
			"k1",
			BStorage::Value::makeArray({
				{
					BStorage::Value::makeByteArray(std::vector<std::byte>({ std::byte(0x10), std::byte(0x20), std::byte(0x30) })),
					BStorage::Value::makeU16(0x4567),
					BStorage::Value::makeOption(nullptr),
					BStorage::Value::makeOption(std::make_unique<BStorage::Value>(BStorage::Value::makeString("test"))),
				},
			}),
		},
		{
			"k2",
			BStorage::Value::makeArray({
				{
					BStorage::Value::makeU16(0x6789),
					BStorage::Value::makeU16(0x1234),
				},
			}),
		},
		{
			"k3",
			BStorage::Value::makeArray({
				{
					BStorage::Value::makeOption(nullptr),
					BStorage::Value::makeOption(std::make_unique<BStorage::Value>(BStorage::Value::makeU8(0xFF))),
				},
			}),
		},
		{
			"k4",
			BStorage::Value::makeArray({}),
		},
	});

	std::vector<char> buffer;
	buffer.resize(1024);
	VecStreamBuf buf(buffer);
	std::ostream os(&buf);

	EXPECT_EQ(initial.writeToStream(os), true);
	std::istream is(&buf);
	const std::optional<BStorage::Value> result = BStorage::Value::readFromStream(is);
	ASSERT_TRUE(result.has_value());
	EXPECT_TRUE(expected.isSameDeepCompare(*result));
}
