// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/noise/internal/handshake_utils.h"

#include <bit>

#include "common_shared/cryptography/noise/cipher_utils.h"
#include "common_shared/cryptography/primitives/hash_functions.h"
#include "common_shared/debug/assert.h"

namespace Noise::Utils
{
	template<CipherStateInstanceTag Tag>
	static void TruncateAndInitializeKey(const HashResult& tempKey, CipherState<Tag>& inOutState)
	{
		static_assert(Cryptography::CipherKeySize == 32, "Unexpected CipherKeySize");
		std::copy(tempKey.raw.begin(), tempKey.raw.begin() + 32, inOutState.cipherKey.raw.begin());
		inOutState.nonce = static_cast<uint64_t>(0);
	}

	SymmetricState initializeSymmetric(const std::string_view protocolName) noexcept
	{
		HashResult h;

		// see https://noiseprotocol.org/noise.html#the-symmetricstate-object
		if (protocolName.length() <= HASHLEN)
		{
			std::copy(protocolName.begin(), protocolName.end(), h.raw.begin());
			// this isn't technically needed because the memory should already be zeroed
			std::fill(h.raw.begin() + protocolName.length(), h.raw.end(), static_cast<uint8_t>(0));
		}
		else
		{
			static_assert(sizeof(*protocolName.data()) == sizeof(uint8_t), "String type should be UTF-8 string with 1 byte per character");
			hash_blake2b(std::span<const uint8_t>(std::bit_cast<const uint8_t*>(protocolName.data()), protocolName.size()), h);
		}

		return SymmetricState{
			.handshakeHash = h.clone(),
			.chainingKey = std::move(h),
			.cipherState = std::nullopt,
		};
	}

	void mixHash(const std::span<const uint8_t> data, SymmetricState& inOutState) noexcept
	{
		// we could pass only handshakeHash to this function, however that would be a bit more error-prone
		hashWithContext_blake2b(inOutState.handshakeHash, data, inOutState.handshakeHash);
	}

	void mixKey(const std::span<const uint8_t> inputKeyMaterial, SymmetricState& inOutState) noexcept
	{
		HashResult tempKey;
		Cryptography::HKDF_blake2b(inOutState.chainingKey, inputKeyMaterial, 2, inOutState.chainingKey, &tempKey, nullptr);
		inOutState.cipherState = CipherStateHandshake{};
		TruncateAndInitializeKey(tempKey, *inOutState.cipherState);
	}

	Cryptography::EncryptResult encryptAndHash(SymmetricState& symmetricState, const std::span<const uint8_t> plaintext, const std::span<uint8_t> outCiphertext)
	{
		if (!symmetricState.cipherState.has_value())
		{
			// even though this case is supported by Noise protocols with names starting with I
			// these protocols are not used in this implementation, therefore treat this as a logical error
			reportDebugError("No encryption key provided");
			return Cryptography::EncryptResult::NoEncryptionKey;
		}

		Cryptography::EncryptResult result = Cryptography::EncryptResult::Success;
		result = encryptWithAd(*symmetricState.cipherState, symmetricState.handshakeHash, plaintext, outCiphertext);
		mixHash(outCiphertext, symmetricState);
		return result;
	}

	Cryptography::DecryptResult decryptAndHash(SymmetricState& symmetricState, const std::span<const uint8_t> ciphertext, const std::span<uint8_t> outPlaintext)
	{
		if (!symmetricState.cipherState.has_value()) [[unlikely]]
		{
			// even though this case is supported by Noise protocols with names starting with I
			// these protocols are not used in this implementation, therefore treat this as a logical error
			reportDebugError("No encryption key provided");
			return Cryptography::DecryptResult::NoEncryptionKey;
		}

		Cryptography::DecryptResult result = Cryptography::DecryptResult::Success;
		result = decryptWithAd(*symmetricState.cipherState, symmetricState.handshakeHash, ciphertext, outPlaintext);
		mixHash(ciphertext, symmetricState);
		return result;
	}

	void split(const SymmetricState& symmetricState, CipherStateSending& c1, CipherStateReceiving& c2, HandshakeRole role)
	{
		HashResult tempKey1;
		HashResult tempKey2;
		Cryptography::HKDF_blake2b(symmetricState.chainingKey, std::span<uint8_t>{}, 2, tempKey1, &tempKey2, nullptr);

		if (role == HandshakeRole::Initiator)
		{
			TruncateAndInitializeKey(tempKey1, c1);
			TruncateAndInitializeKey(tempKey2, c2);
		}
		else
		{
			TruncateAndInitializeKey(tempKey1, c2);
			TruncateAndInitializeKey(tempKey2, c1);
		}
	}

	int writeDataToBuffer(const std::span<const uint8_t> data, const std::span<std::byte> inOutBuffer, size_t& inOutWritePos) noexcept
	{
		if (inOutBuffer.size() < (inOutWritePos + data.size()))
		{
			return -1;
		}

		if (data.size() == 0)
		{
			return 0;
		}

		static_assert(sizeof(data[0]) == sizeof(inOutBuffer[0]), "Both data and buffer should be arrays of bytes");
		std::copy(data.begin(), data.end(), std::bit_cast<uint8_t*>(inOutBuffer.data()) + inOutWritePos);
		inOutWritePos += data.size();

		return 0;
	}

	int readDataFromBuffer(const std::span<const std::byte> buffer, const std::span<uint8_t> outData, size_t& inOutReadPos) noexcept
	{
		if (buffer.size() < (inOutReadPos + outData.size()))
		{
			return -1;
		}

		if (outData.size() == 0)
		{
			return 0;
		}

		static_assert(sizeof(outData[0]) == sizeof(buffer[0]), "Both data and buffer should be arrays of bytes");
		std::copy(buffer.begin() + inOutReadPos, buffer.begin() + (inOutReadPos + outData.size()), std::bit_cast<std::byte*>(outData.data()));
		inOutReadPos += outData.size();

		return 0;
	}
} // namespace Noise::Utils
