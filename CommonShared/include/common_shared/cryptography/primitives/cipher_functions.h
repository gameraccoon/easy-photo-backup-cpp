// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/types/cipher_types.h"

namespace Cryptography
{
	[[nodiscard]] EncryptResult encrypt_chacha20poly1305(
		const CipherKey& key,
		const Nonce nonce,
		const std::span<const uint8_t> associatedData,
		const std::span<const uint8_t> plaintext,
		const std::span<uint8_t> outCiphertext
	) noexcept;

	// returns 0 if authentication succeeds, otherwise returns a non-zero error code
	[[nodiscard]] DecryptResult decrypt_chacha20poly1305(
		const CipherKey& key,
		const Nonce nonce,
		const std::span<const uint8_t> associatedData,
		const std::span<const uint8_t> ciphertext,
		const std::span<uint8_t> outPlaintext
	) noexcept;
}
