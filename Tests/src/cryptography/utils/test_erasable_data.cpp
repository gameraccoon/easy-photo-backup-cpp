// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <gtest/gtest.h>

#include "common_shared/cryptography/utils/erasable_data.h"

TEST(CryptographyErasableData, ArrayWithData_CryptoWipe_DataIsZeroed)
{
	std::array<std::byte, 4> rawData = {};
	for (size_t i = 0; i < 4; ++i)
	{
		rawData[i] = static_cast<std::byte>(i + 1);
	}

	Cryptography::cryptoWipeRawData(rawData);

	EXPECT_EQ(rawData[0], std::byte(0));
	EXPECT_EQ(rawData[1], std::byte(0));
	EXPECT_EQ(rawData[2], std::byte(0));
	EXPECT_EQ(rawData[3], std::byte(0));
}

TEST(CryptographyErasableData, ByteSequence_Created_Empty)
{
	using TestData = Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, 4>;

	const TestData data;
	ASSERT_EQ(data.size(), size_t(4));
	ASSERT_EQ(data.raw.size(), size_t(4));

	EXPECT_EQ(data.raw[0], std::byte(0));
	EXPECT_EQ(data.raw[1], std::byte(0));
	EXPECT_EQ(data.raw[2], std::byte(0));
	EXPECT_EQ(data.raw[3], std::byte(0));
}

TEST(CryptographyErasableData, ByteSequenceWithData_AccessedAsMutSlice_AccessedCorrectData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<std::byte>(i + 1);
	}

	const std::span<std::byte> ref = data;

	EXPECT_EQ(ref.size(), size_t(4));
	EXPECT_EQ(ref[0], std::byte(1));
	EXPECT_EQ(ref[1], std::byte(2));
	EXPECT_EQ(ref[2], std::byte(3));
	EXPECT_EQ(ref[3], std::byte(4));
}

TEST(CryptographyErasableData, ByteSequenceWithData_AccessedAsConstSlice_AccessedCorrectData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<std::byte>(i + 1);
	}

	const std::span<const std::byte> ref = data;

	EXPECT_EQ(ref.size(), size_t(4));
	EXPECT_EQ(ref[0], std::byte(1));
	EXPECT_EQ(ref[1], std::byte(2));
	EXPECT_EQ(ref[2], std::byte(3));
	EXPECT_EQ(ref[3], std::byte(4));
}

TEST(CryptographyErasableData, ByteSequenceWithData_Move_MovedToArrayContainsData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<std::byte>(i + 1);
	}

	const TestData data2 = std::move(data);

	EXPECT_EQ(data2.raw[0], std::byte(1));
	EXPECT_EQ(data2.raw[1], std::byte(2));
	EXPECT_EQ(data2.raw[2], std::byte(3));
	EXPECT_EQ(data2.raw[3], std::byte(4));
}

TEST(CryptographyErasableData, ByteSequenceWithData_MoveAssign_MovedToArrayContainsData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<std::byte>(i + 1);
	}

	TestData data2;
	data2 = std::move(data);

	EXPECT_EQ(data2.raw[0], std::byte(1));
	EXPECT_EQ(data2.raw[1], std::byte(2));
	EXPECT_EQ(data2.raw[2], std::byte(3));
	EXPECT_EQ(data2.raw[3], std::byte(4));
}

TEST(CryptographyErasableData, ByteSequenceWithData_Clone_ClonedToArrayContainsData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<std::byte>(i + 1);
	}

	const TestData data2 = data.clone();

	EXPECT_EQ(data2.raw[0], std::byte(1));
	EXPECT_EQ(data2.raw[1], std::byte(2));
	EXPECT_EQ(data2.raw[2], std::byte(3));
	EXPECT_EQ(data2.raw[3], std::byte(4));
}
