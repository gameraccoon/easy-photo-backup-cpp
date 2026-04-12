// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/types/cipher_types.h"

namespace Cryptography
{
	[[nodiscard]] EncryptResult encrypt_chacha20poly1305(
		const CipherKey& key,
		const Nonce nonce,
		const std::span<const std::byte> associatedData,
		const std::span<const std::byte> plaintext,
		const std::span<std::byte> outCiphertext
	) noexcept;

	// returns 0 if authentication succeeds, otherwise returns a non-zero error code
	[[nodiscard]] DecryptResult decrypt_chacha20poly1305(
		const CipherKey& key,
		const Nonce nonce,
		const std::span<const std::byte> associatedData,
		const std::span<const std::byte> ciphertext,
		const std::span<std::byte> outPlaintext
	) noexcept;
}
