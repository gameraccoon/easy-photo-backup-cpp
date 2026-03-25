// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/keypair.h"

namespace Cryptography
{
	using DhResult = ByteSequence<Tag::DhResult, DHLEN>;

	Keypair generateKeypair_x25519();

	DhResult diffieHellman_x25519(const SecretKey& secretKey, const PublicKey& publicKey);
}
