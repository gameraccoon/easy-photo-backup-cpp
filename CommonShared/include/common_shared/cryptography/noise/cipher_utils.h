// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include "common_shared/cryptography/noise/cipher_types.h"

namespace Noise::Utils
{
	// see the specification here: https://noiseprotocol.org/noise.html#processing-rules

	[[nodiscard]] Cryptography::EncryptResult encryptWithAd(CipherStateSending& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> plaintext, const std::span<uint8_t> outCiphertext);
	[[nodiscard]] Cryptography::DecryptResult decryptWithAd(CipherStateReceiving& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> ciphertext, const std::span<uint8_t> outPlaintext);

	[[nodiscard]] Cryptography::EncryptResult encryptWithAd(CipherStateHandshake& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> plaintext, const std::span<uint8_t> outCiphertext);
	[[nodiscard]] Cryptography::DecryptResult decryptWithAd(CipherStateHandshake& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> ciphertext, const std::span<uint8_t> outPlaintext);
}
