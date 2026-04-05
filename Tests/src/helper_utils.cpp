// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "tests/helper_utils.h"

#include <algorithm>

void hexCharToInt(const char ch, uint8_t& res)
{
	if (ch >= '0' && ch <= '9')
	{
		res = ch - '0';
		return;
	}

	if (ch >= 'A' && ch <= 'F')
	{
		res = 10 + (ch - 'A');
		return;
	}

	if (ch >= 'a' && ch <= 'f')
	{
		res = 10 + (ch - 'a');
		return;
	}

	printf("unknown HEX character: '%c' with code %u", ch, ch);

	FAIL();
}

static void assertEven(size_t n)
{
	ASSERT_EQ(n % 2, size_t(0)) << "Only whole bytes expected in hex, pad with 0";
}

std::vector<uint8_t> hexToBytes(const std::string_view inString)
{
	std::vector<uint8_t> outVector;
	assertEven(inString.size());
	outVector.resize(inString.size() / 2);
	for (size_t i = 0; i < outVector.size(); ++i)
	{
		uint8_t v1;
		uint8_t v2;
		hexCharToInt(inString[i * 2], v1);
		hexCharToInt(inString[i * 2 + 1], v2);
		outVector[i] = (v1 << 4) | v2;
	}
	return outVector;
}

std::vector<uint8_t> strToBytes(const std::string_view inString)
{
	std::vector<uint8_t> outVector;
	outVector.reserve(inString.size());
	for (const char ch : inString)
	{
		outVector.push_back(static_cast<uint8_t>(ch));
	}
	return outVector;
}

void appendHexBytes(const std::string_view inString, std::vector<uint8_t>& inOutVec)
{
	assertEven(inString.size());
	const size_t writePos = inOutVec.size();
	const size_t byteSize = inString.size() / 2;
	inOutVec.resize(writePos + byteSize);
	for (size_t i = 0; i < byteSize; ++i)
	{
		uint8_t v1;
		uint8_t v2;
		hexCharToInt(inString[i * 2], v1);
		hexCharToInt(inString[i * 2 + 1], v2);
		inOutVec[writePos + i] = (v1 << 4) | v2;
	}
}

bool isAllZeroes(const std::span<const uint8_t> data)
{
	return std::all_of(data.begin(), data.end(), [](uint8_t v) { return v == static_cast<uint8_t>(0); });
}
