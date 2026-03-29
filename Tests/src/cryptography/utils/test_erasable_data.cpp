// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <gtest/gtest.h>

#include "common_shared/cryptography/utils/erasable_data.h"

TEST(CryptographyErasableData, ArrayWithData_CryptoWipe_DataIsZeroed)
{
	std::array<uint8_t, 4> rawData;
	for (size_t i = 0; i < 4; ++i)
	{
		rawData[i] = static_cast<uint8_t>(i + 1);
	}

	Cryptography::cryptoWipeRawData(rawData);

	EXPECT_EQ(rawData[0], 0);
	EXPECT_EQ(rawData[1], 0);
	EXPECT_EQ(rawData[2], 0);
	EXPECT_EQ(rawData[3], 0);
}

TEST(CryptographyErasableData, ByteSequence_Created_Empty)
{
	using TestData = Cryptography::ByteSequence<Cryptography::Tag::TempInternalBuffer, 4>;

	const TestData data;
	ASSERT_EQ(data.size(), size_t(4));
	ASSERT_EQ(data.raw.size(), size_t(4));

	EXPECT_EQ(data.raw[0], 0);
	EXPECT_EQ(data.raw[1], 0);
	EXPECT_EQ(data.raw[2], 0);
	EXPECT_EQ(data.raw[3], 0);
}

TEST(CryptographyErasableData, DynByteSequence_Created_Empty)
{
	using TestData = Cryptography::DynByteSequence;

	const TestData data;
	EXPECT_TRUE(data.raw.empty());
	EXPECT_EQ(data.size(), size_t(0));
}

TEST(CryptographyErasableData, DynByteSequence_CreatedFromVector_VectorDataIsMoved)
{
	using TestData = Cryptography::DynByteSequence;

	std::vector<uint8_t> rawData;
	rawData.reserve(4);
	for (size_t i = 0; i < 4; ++i)
	{
		rawData.push_back(static_cast<uint8_t>(i + 1));
	}

	const TestData data = TestData::fromVector(std::move(rawData));

	ASSERT_EQ(rawData.size(), size_t(0));
	ASSERT_EQ(data.size(), size_t(4));
	EXPECT_EQ(data.raw[0], 1);
	EXPECT_EQ(data.raw[1], 2);
	EXPECT_EQ(data.raw[2], 3);
	EXPECT_EQ(data.raw[3], 4);
}

TEST(CryptographyErasableData, DynByteSequenceWithData_ClearResizeToSameSize_DataIsZeroed)
{
	using TestData = Cryptography::DynByteSequence;

	TestData data;
	data.clearResize(4);
	ASSERT_EQ(data.size(), size_t(4));
	ASSERT_EQ(data.raw.size(), size_t(4));

	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	data.clearResize(4);

	ASSERT_EQ(data.size(), size_t(4));
	EXPECT_EQ(data.raw[0], 0);
	EXPECT_EQ(data.raw[1], 0);
	EXPECT_EQ(data.raw[2], 0);
	EXPECT_EQ(data.raw[3], 0);
}

TEST(CryptographyErasableData, ByteSequenceWithData_AccessedAsMutSlice_AccessedCorrectData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::Tag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	const std::span<uint8_t> ref = data;

	EXPECT_EQ(ref.size(), size_t(4));
	EXPECT_EQ(ref[0], 1);
	EXPECT_EQ(ref[1], 2);
	EXPECT_EQ(ref[2], 3);
	EXPECT_EQ(ref[3], 4);
}

TEST(CryptographyErasableData, ByteSequenceWithData_AccessedAsConstSlice_AccessedCorrectData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::Tag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	const std::span<const uint8_t> ref = data;

	EXPECT_EQ(ref.size(), size_t(4));
	EXPECT_EQ(ref[0], 1);
	EXPECT_EQ(ref[1], 2);
	EXPECT_EQ(ref[2], 3);
	EXPECT_EQ(ref[3], 4);
}

TEST(CryptographyErasableData, DynByteSequenceWithData_AccessedAsMutSlice_AccessedCorrectData)
{
	using TestData = Cryptography::DynByteSequence;

	TestData data;
	data.clearResize(4);
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	const std::span<uint8_t> ref = data;

	EXPECT_EQ(ref.size(), size_t(4));
	EXPECT_EQ(ref[0], 1);
	EXPECT_EQ(ref[1], 2);
	EXPECT_EQ(ref[2], 3);
	EXPECT_EQ(ref[3], 4);
}

TEST(CryptographyErasableData, DynByteSequenceWithData_AccessedAsConstSlice_AccessedCorrectData)
{
	using TestData = Cryptography::DynByteSequence;

	TestData data;
	data.clearResize(4);
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	const std::span<const uint8_t> ref = data;

	EXPECT_EQ(ref.size(), size_t(4));
	EXPECT_EQ(ref[0], 1);
	EXPECT_EQ(ref[1], 2);
	EXPECT_EQ(ref[2], 3);
	EXPECT_EQ(ref[3], 4);
}

TEST(CryptographyErasableData, ByteSequenceWithData_Move_MovedToArrayContainsData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::Tag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	const TestData data2 = std::move(data);

	EXPECT_EQ(data2.raw[0], 1);
	EXPECT_EQ(data2.raw[1], 2);
	EXPECT_EQ(data2.raw[2], 3);
	EXPECT_EQ(data2.raw[3], 4);
}

TEST(CryptographyErasableData, ByteSequenceWithData_MoveAssign_MovedToArrayContainsData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::Tag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	TestData data2;
	data2 = std::move(data);

	EXPECT_EQ(data2.raw[0], 1);
	EXPECT_EQ(data2.raw[1], 2);
	EXPECT_EQ(data2.raw[2], 3);
	EXPECT_EQ(data2.raw[3], 4);
}

TEST(CryptographyErasableData, ByteSequenceWithData_Clone_ClonedToArrayContainsData)
{
	using TestData = Cryptography::ByteSequence<Cryptography::Tag::TempInternalBuffer, 4>;

	TestData data;
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	const TestData data2 = data.clone();

	EXPECT_EQ(data2.raw[0], 1);
	EXPECT_EQ(data2.raw[1], 2);
	EXPECT_EQ(data2.raw[2], 3);
	EXPECT_EQ(data2.raw[3], 4);
}

TEST(CryptographyErasableData, DynByteSequenceWithData_Move_MovedToArrayContainsData)
{
	using TestData = Cryptography::DynByteSequence;

	TestData data;
	data.clearResize(4);
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	const TestData data2 = std::move(data);

	ASSERT_EQ(data.size(), size_t(0));
	ASSERT_EQ(data2.size(), size_t(4));
	EXPECT_EQ(data2.raw[0], 1);
	EXPECT_EQ(data2.raw[1], 2);
	EXPECT_EQ(data2.raw[2], 3);
	EXPECT_EQ(data2.raw[3], 4);
}

TEST(CryptographyErasableData, DynByteSequenceWithData_MoveAssign_DataIsMoved)
{
	using TestData = Cryptography::DynByteSequence;

	TestData data;
	data.clearResize(4);
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	TestData data2;
	data2 = std::move(data);

	ASSERT_EQ(data.size(), size_t(0));
	ASSERT_EQ(data2.size(), size_t(4));
	EXPECT_EQ(data2.raw[0], 1);
	EXPECT_EQ(data2.raw[1], 2);
	EXPECT_EQ(data2.raw[2], 3);
	EXPECT_EQ(data2.raw[3], 4);
}

TEST(CryptographyErasableData, DynByteSequenceWithData_Clone_ClonedToArrayContainsData)
{
	using TestData = Cryptography::DynByteSequence;

	TestData data;
	data.clearResize(4);
	for (size_t i = 0; i < 4; ++i)
	{
		data.raw[i] = static_cast<uint8_t>(i + 1);
	}

	const TestData data2 = data.clone();

	EXPECT_EQ(data2.raw[0], 1);
	EXPECT_EQ(data2.raw[1], 2);
	EXPECT_EQ(data2.raw[2], 3);
	EXPECT_EQ(data2.raw[3], 4);
}
