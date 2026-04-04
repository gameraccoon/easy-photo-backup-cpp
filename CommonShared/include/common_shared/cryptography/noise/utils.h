// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstddef>
#include <string_view>

#include "common_shared/cryptography/noise/types.h"

namespace Noise::Utils
{
	// see the specification here: https://noiseprotocol.org/noise.html#processing-rules

	void initializeKey(Cryptography::CipherKey&& key, CipherState& inOutState);
	SymmetricState initializeSymmetric(const std::string_view protocolName);
	void mixHash(const std::span<const uint8_t> data, SymmetricState& inOutState);
	void mixKey(const std::span<const uint8_t> inputKeyMaterial, SymmetricState& inOutState);
	// returns zero on success, non-zero on failure (not enough space in the buffer)
	int writeDataToBuffer(const std::span<const uint8_t>& data, const std::span<std::byte> inOutBuffer, size_t& inOutWritePos);
}
