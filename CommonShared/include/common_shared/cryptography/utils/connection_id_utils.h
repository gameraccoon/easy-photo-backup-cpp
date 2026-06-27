// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/types/dh_types.h"
#include "common_shared/cryptography/types/hash_types.h"

#pragma once

namespace Cryptography
{
	HashResult generateConnectionId(const PublicKey& clientPublicKey, const PublicKey& serverPublicKey);
}
