// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <span>

#include "common_shared/cryptography/types/hash_types.h"

namespace Cryptography
{
#ifdef WITH_TESTS
	// it is only used for the HKDF implementations, but we still want to test it
	void HMAC_blake2b(const HashResult& key, std::span<const uint8_t> data, HashResult& outMac);
#endif

	void HKDF_blake2b(
		const HashResult& chainingKey,
		const DynByteSequence& inputKeyMaterial,
		uint8_t numOutputs,
		HashResult& output1,
		HashResult* output2,
		HashResult* output3
	);
} // namespace Cryptography
