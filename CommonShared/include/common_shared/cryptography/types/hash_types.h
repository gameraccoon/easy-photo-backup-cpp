// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/utils/erasable_data.h"

namespace Cryptography
{
	constexpr std::size_t HASHLEN = 32;
	constexpr std::size_t BLOCKLEN = 64;

	using HashResult = ByteSequence<Tag::HashResult, HASHLEN>;
} // namespace Cryptography
