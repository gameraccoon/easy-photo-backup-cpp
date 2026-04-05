// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

void hexCharToInt(const char ch, uint8_t& res);
std::vector<uint8_t> hexToBytes(const std::string_view inString);
std::vector<uint8_t> strToBytes(const std::string_view inString);
void appendHexBytes(const std::string_view inString, std::vector<uint8_t>& inOutVec);
bool isAllZeroes(const std::span<const uint8_t> data);

template<size_t Size>
void vectorToArray(const std::span<const uint8_t> inVector, std::array<uint8_t, Size>& outArray)
{
	ASSERT_EQ(inVector.size(), outArray.size());
	for (size_t i = 0; i < outArray.size(); ++i)
	{
		outArray[i] = inVector[i];
	}
}

template<size_t Size>
std::array<uint8_t, Size> vectorToArray(const std::span<const uint8_t> inVector)
{
	std::array<uint8_t, Size> result;
	vectorToArray(inVector, result);
	return result;
}

template<size_t Size>
void vectorToByteArray(const std::span<const uint8_t> inVector, std::array<std::byte, Size>& outArray)
{
	ASSERT_EQ(inVector.size(), outArray.size());
	for (size_t i = 0; i < outArray.size(); ++i)
	{
		outArray[i] = static_cast<std::byte>(inVector[i]);
	}
}

template<size_t Size>
std::array<std::byte, Size> vectorToByteArray(const std::span<const uint8_t> inVector)
{
	std::array<std::byte, Size> result;
	vectorToByteArray(inVector, result);
	return result;
}
