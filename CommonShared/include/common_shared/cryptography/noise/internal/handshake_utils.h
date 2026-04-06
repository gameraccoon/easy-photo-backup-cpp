// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstddef>
#include <string_view>

#include "common_shared/cryptography/noise/handshake_types.h"

namespace Noise::Utils
{
	// see the specification here: https://noiseprotocol.org/noise.html#processing-rules

	enum class HandshakeRole
	{
		Initiator,
		Responder,
	};

	// cipher state functions
	[[nodiscard]] Cryptography::EncryptResult encryptWithAd(CipherStateSending& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> plaintext, const std::span<uint8_t> outCiphertext);
	[[nodiscard]] Cryptography::DecryptResult decryptWithAd(CipherStateReceiving& cipherState, const std::span<const uint8_t> associatedData, const std::span<const uint8_t> ciphertext, const std::span<uint8_t> outPlaintext);

	// symmetric state functions
	[[nodiscard]] SymmetricState initializeSymmetric(const std::string_view protocolName) noexcept;
	void mixHash(const std::span<const uint8_t> data, SymmetricState& inOutState) noexcept;
	void mixKey(const std::span<const uint8_t> inputKeyMaterial, SymmetricState& inOutState) noexcept;
	[[nodiscard]] Cryptography::EncryptResult encryptAndHash(SymmetricState& symmetricState, const std::span<const uint8_t> plaintext, const std::span<uint8_t> outCiphertext);
	[[nodiscard]] Cryptography::DecryptResult decryptAndHash(SymmetricState& symmetricState, const std::span<const uint8_t> ciphertext, const std::span<uint8_t> outPlaintext);
	void split(const SymmetricState& symmetricState, CipherStateSending& c1, CipherStateReceiving& c2, HandshakeRole role);
	// returns zero on success, non-zero on failure (not enough space in the buffer)
	[[nodiscard]] int writeDataToBuffer(const std::span<const uint8_t> data, const std::span<std::byte> inOutBuffer, size_t& inOutWritePos) noexcept;
	// returns zero on success, non-zero on failure (not enough space in the buffer)
	[[nodiscard]] int readDataFromBuffer(const std::span<const std::byte> buffer, const std::span<uint8_t> outData, size_t& inOutReadPos) noexcept;
} // namespace Noise::Utils
