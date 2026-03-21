// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <cstdint>
#include <span>

namespace Cryptography
{
	// fills the span with random data produced by the operating system random (slow)
	void fillWithRandomBytes(std::span<uint8_t> outNumber);
}
