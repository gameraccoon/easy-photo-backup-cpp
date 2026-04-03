// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <string_view>

#include "common_shared/cryptography/noise/types.h"

namespace Noise::Utils
{
	// see the specification here: https://noiseprotocol.org/noise.html#processing-rules

	SymmetricState initializeSymmetric(const std::string_view protocolName);
	void mixHash(const std::span<const uint8_t> data, HashResult& inOutH);
}
