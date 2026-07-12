// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/utils/short_authentification_string_utils.h"

#include "common_shared/debug/assert.h"
#include "common_shared/serialization/number_serialization.h"
#include "common_shared/cryptography/primitives/hash_functions.h"

namespace Cryptography
{
	static constexpr std::string_view sasContextString = "HMAC salt v1";

	std::string generateSas(const HashResult& handshakeHash, uint8_t digits) noexcept
	{
		assertFatalRelease(digits < std::numeric_limits<uint64_t>::digits10, "generateSas requested more digits than possible {}", digits);

		HashResult hmac;
		HMAC_blake2b(handshakeHash, std::as_bytes(std::span(sasContextString)), hmac);

		uint64_t denominator = 1;
		for (uint8_t i = 0; i < digits; ++i)
		{
			denominator *= 10;
		}
		const uint64_t first8bytes = Serialization::readUint64(std::span<const std::byte>(hmac.raw.begin(), hmac.raw.begin() + 8));
		return std::to_string(first8bytes % denominator);
	}
}
