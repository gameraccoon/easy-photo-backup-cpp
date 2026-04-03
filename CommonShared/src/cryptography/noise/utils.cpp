// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/noise/utils.h"

#include <bit>

#include "common_shared/cryptography/primitives/hash_functions.h"

namespace Noise::Utils
{
	SymmetricState initializeSymmetric(const std::string_view protocolName)
	{
		HashResult h;

		// see https://noiseprotocol.org/noise.html#the-symmetricstate-object
		if (protocolName.length() <= HASHLEN)
		{
			std::copy(protocolName.begin(), protocolName.end(), h.raw.begin());
			// this isn't technically needed because the memory should already be zeroed
			std::fill(h.raw.begin() + protocolName.length(), h.raw.end(), static_cast<uint8_t>(0));
		}
		else
		{
			static_assert(sizeof(*protocolName.data()) == sizeof(uint8_t), "String type should be UTF-8 string with 1 byte per character");
			hash_blake2b(std::span<const uint8_t>(std::bit_cast<const uint8_t*>(protocolName.data()), protocolName.size()), h);
		}

		return SymmetricState{
			.handshakeHash = h.clone(),
			.chainingKey = std::move(h),
		};
	}

	void mixHash(const std::span<const uint8_t> data, SymmetricState& inOutState)
	{
		// we could pass only handshakeHash to this function, however that would be a bit more error-prone
		hashWithContext_blake2b(inOutState.handshakeHash, data, inOutState.handshakeHash);
	}

	int appendDataToBuffer(const std::span<const uint8_t>& data, const std::span<std::byte> inOutBuffer, size_t& inOutWritePos)
	{
		if (inOutBuffer.size() < (inOutWritePos + data.size()))
		{
			return -1;
		}

		if (data.size() == 0)
		{
			return 0;
		}

		static_assert(sizeof(data[0]) == sizeof(inOutBuffer[0]));
		std::copy(data.begin(), data.end(), std::bit_cast<uint8_t*>(inOutBuffer.data()) + inOutWritePos);
		inOutWritePos += data.size();

		return 0;
	}
} // namespace Noise::Utils
