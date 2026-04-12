// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

void hexCharToInt(const char ch, std::byte& res);
std::vector<std::byte> hexToBytes(const std::string_view inString);
std::vector<std::byte> strToBytes(const std::string_view inString);
void appendHexBytes(const std::string_view inString, std::vector<std::byte>& inOutVec);
bool isAllZeroes(const std::span<const std::byte> data);

template<size_t Size>
void vectorToArray(const std::span<const std::byte> inVector, std::array<std::byte, Size>& outArray)
{
	ASSERT_EQ(inVector.size(), outArray.size());
	for (size_t i = 0; i < outArray.size(); ++i)
	{
		outArray[i] = inVector[i];
	}
}

template<size_t Size>
std::array<std::byte, Size> vectorToArray(const std::span<const std::byte> inVector)
{
	std::array<std::byte, Size> result;
	vectorToArray(inVector, result);
	return result;
}
