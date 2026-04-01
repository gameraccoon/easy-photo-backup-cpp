// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/utils/erasable_data.h"

namespace Cryptography
{
	constexpr size_t CipherKeySize = 32;
	constexpr size_t NonceSize = 8;
	constexpr size_t MaxMessageSize = 65535;

	using CipherKey = ByteSequence<Tag::CipherKey, CipherKeySize>;
	using Nonce = uint64_t;
} // namespace Cryptography
