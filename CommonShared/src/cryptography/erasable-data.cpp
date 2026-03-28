// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/erasable-data.h"

#include <monocypher.h>

namespace Cryptography
{
	void cryptoWipeRawData(std::span<uint8_t> rawData)
	{
		crypto_wipe(rawData.data(), rawData.size());
	}

	using StaticAssertTestByteSequence = ByteSequence<Tag::TempInternalBuffer, 60>;
	// these are important for some of the static asserts to work
	// (some require using sizeof when passed by reference)
	static_assert(sizeof(StaticAssertTestByteSequence::raw) == 60);
	static_assert(sizeof(StaticAssertTestByteSequence) == 60);
} // namespace Cryptography
