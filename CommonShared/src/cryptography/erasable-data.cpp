// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/erasable-data.h"

#include "monocypher.h"

namespace Cryptography
{
	void secureErase(std::span<uint8_t> rawData)
	{
		crypto_wipe(rawData.data(), rawData.size());
	}
} // namespace Cryptography
