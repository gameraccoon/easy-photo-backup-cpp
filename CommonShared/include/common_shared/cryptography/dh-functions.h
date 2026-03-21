// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/keypair.h"

namespace Cryptography
{
	Keypair generateKeypair();

	DhResult diffieHellman(const SecretKey& secretKey, const PublicKey& publicKey);
} // namespace Cryptography
