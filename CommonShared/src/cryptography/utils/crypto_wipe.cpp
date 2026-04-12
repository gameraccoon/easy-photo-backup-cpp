// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/utils/crypto_wipe.h"

#include <monocypher.h>

namespace Cryptography
{
	void cryptoWipeRawData(std::span<std::byte> rawData) noexcept
	{
		crypto_wipe(rawData.data(), rawData.size());
	}

	void cryptoWipeRawMemory(void* memoryStart, size_t memorySizeBytes) noexcept
	{
		crypto_wipe(memoryStart, memorySizeBytes);
	}
} // namespace Cryptography
