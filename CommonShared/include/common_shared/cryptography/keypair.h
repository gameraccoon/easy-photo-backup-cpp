// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/erasable-data.h"

namespace Cryptography
{
	constexpr std::size_t DHLEN = 32;

	using PublicKey = ByteSequence<Tag::PublicKey, DHLEN>;
	using SecretKey = ByteSequence<Tag::SecretKey, DHLEN>;

	struct Keypair
	{
		PublicKey publicKey;
		SecretKey secretKey;
	};
} // namespace Cryptography
