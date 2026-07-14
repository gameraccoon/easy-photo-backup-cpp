// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/cryptography/primitives/hash_functions.h"

#include <cstring>

#include <monocypher.h>

#include "common_shared/cryptography/utils/erasable_data.h"
#include "common_shared/debug/assert.h"

namespace Cryptography
{
	// compile-time checked len (prefer this when possible)
	template<size_t len, ByteSequenceTag tag>
	static void hashUpdate_blake2b(crypto_blake2b_ctx* context, const ByteSequence<tag, len>& data) noexcept
	{
		static_assert(sizeof(*data.raw.data()) == sizeof(uint8_t), "Expected data to be a byte array");
		crypto_blake2b_update(context, reinterpret_cast<const uint8_t*>(data.raw.data()), data.raw.size());
	}

	// dynamic len raw (avoid when possible)
	static void hashUpdateDyn_blake2b(crypto_blake2b_ctx* context, const std::span<const std::byte> data) noexcept
	{
		static_assert(sizeof(*data.data()) == sizeof(uint8_t), "Expected data to be a byte array");
		crypto_blake2b_update(context, reinterpret_cast<const uint8_t*>(data.data()), data.size());
	}

	template<size_t len, ByteSequenceTag tag>
	static void hashFinal_blake2b(crypto_blake2b_ctx* context, ByteSequence<tag, len>& data) noexcept
	{
		static_assert(sizeof(*data.raw.data()) == sizeof(uint8_t), "Expected data to be a byte array");
		static_assert(sizeof(data.raw) == len, "Unexpected result buffer size");
		assertFatalRelease(data.raw.size() == len, "Unexpected result buffer size");
		assertFatalRelease(context->hash_size == len, "The hash size is not same as the result buffer size");
		crypto_blake2b_final(context, reinterpret_cast<uint8_t*>(data.raw.data()));
	}

	void hash_blake2b(std::span<const std::byte> data, HashResult& outHash) noexcept
	{
		crypto_blake2b_ctx context{};
		crypto_blake2b_init(&context, HASHLEN);
		hashUpdateDyn_blake2b(&context, data);
		hashFinal_blake2b<HASHLEN>(&context, outHash);
	}

	void hashWithContext_blake2b(std::span<const std::byte> con, std::span<const std::byte> data, HashResult& outHash) noexcept
	{
		crypto_blake2b_ctx context{};
		crypto_blake2b_init(&context, HASHLEN);
		hashUpdateDyn_blake2b(&context, con);
		hashUpdateDyn_blake2b(&context, data);
		hashFinal_blake2b<HASHLEN>(&context, outHash);
	}

	void HMAC_blake2b(const HashResult& key, const std::span<const std::byte> data, HashResult& outMac) noexcept
	{
		// check https://www.ietf.org/rfc/rfc2104.txt

		ByteSequence<ByteSequenceTag::TempInternalBuffer, BLOCKLEN> iPad; // inner padding
		ByteSequence<ByteSequenceTag::TempInternalBuffer, BLOCKLEN> oPad; // outer padding
		crypto_blake2b_ctx context{};

		std::memset(iPad.raw.data(), 0x36, iPad.raw.size());
		std::memset(oPad.raw.data(), 0x5c, oPad.raw.size());

		static_assert(sizeof(key.raw) == HASHLEN, "Key size for HMAC is not of HASHLEN");
		assertFatalRelease(key.raw.size() == HASHLEN, "Key size for HMAC is not of HASHLEN");
		static_assert(sizeof(iPad.raw) >= sizeof(key.raw), "iPad size can't be less than key size");
		assertFatalRelease(iPad.raw.size() >= key.raw.size(), "iPad size can't be less than key size");
		static_assert(sizeof(oPad.raw) >= sizeof(key.raw), "oPad size can't be less than key size");
		assertFatalRelease(oPad.raw.size() >= key.raw.size(), "oPad size can't be less than key size");

		for (size_t i = 0; i < HASHLEN; ++i)
		{
			iPad.raw[i] ^= key.raw[i];
			oPad.raw[i] ^= key.raw[i];
		}

		crypto_blake2b_init(&context, HASHLEN);
		hashUpdate_blake2b<BLOCKLEN>(&context, iPad);
		hashUpdateDyn_blake2b(&context, data);
		hashFinal_blake2b<HASHLEN>(&context, outMac);

		crypto_blake2b_init(&context, HASHLEN);
		hashUpdate_blake2b<BLOCKLEN>(&context, oPad);
		hashUpdate_blake2b<HASHLEN>(&context, outMac);
		hashFinal_blake2b<HASHLEN>(&context, outMac);
	}

	void HKDF_blake2b(
		const HashResult& chainingKey,
		std::span<const std::byte> inputKeyMaterial,
		int numOutputs,
		HashResult& output1,
		HashResult* output2,
		HashResult* output3
	) noexcept
	{
		if (numOutputs != 1 && numOutputs != 2 && numOutputs != 3)
		{
			reportFatalReleaseError("Wrong numOutputs value {}", numOutputs);
		}

		ByteSequence<ByteSequenceTag::HashResult, HASHLEN> tempKey;

		HMAC_blake2b(chainingKey, inputKeyMaterial, tempKey);
		HMAC_blake2b(tempKey, std::array<std::byte, 1>{ { std::byte(0x01) } }, output1);

		if (numOutputs == 1)
		{
			return;
		}

		if (output2 == nullptr)
		{
			reportFatalReleaseError("Argument output2 was not provided for numOutputs > 1");
			return;
		}

		ByteSequence<ByteSequenceTag::TempInternalBuffer, HASHLEN + 1> temp;
		std::copy(output1.raw.begin(), output1.raw.end(), temp.raw.begin());
		temp.raw[HASHLEN] = std::byte(0x02);
		HMAC_blake2b(tempKey, temp, *output2);

		if (numOutputs == 2)
		{
			return;
		}

		if (output3 == nullptr)
		{
			reportFatalReleaseError("Argument output3 was not provided for numOutputs > 2");
			return;
		}

		std::copy(output2->raw.begin(), output2->raw.end(), temp.raw.begin());
		temp.raw[HASHLEN] = std::byte(0x03);
		HMAC_blake2b(tempKey, temp, *output3);
	}

	int hashFile(const std::filesystem::path& path, HashResult& outHash) noexcept
	{
		int errorCode = 0;
		crypto_blake2b_ctx context{};
		crypto_blake2b_init(&context, HASHLEN);

		try
		{
			std::ifstream stream;
			stream.open(path, std::ios::binary | std::ios::in);

			constexpr size_t bufferSize = BLOCKLEN;
			ByteSequence<ByteSequenceTag::TempInternalBuffer, bufferSize> buffer;

			while (stream.read(reinterpret_cast<char*>(buffer.raw.data()), buffer.raw.size()))
			{
				hashUpdateDyn_blake2b(&context, buffer);
			}

			if (const size_t remaining = stream.gcount(); remaining > 0)
			{
				hashUpdateDyn_blake2b(&context, std::span<std::byte>(buffer.raw.data(), remaining));
			}

			if (stream.bad())
			{
				errorCode = -1;
			}

			stream.close();
		}
		catch (const std::exception& e)
		{
			Debug::Log::printDebug("Exception thrown when trying to compute hash: {}", e.what());
			errorCode = -1;
		}

		hashFinal_blake2b<HASHLEN>(&context, outHash);
		return errorCode;
	}

	int hashFileBytes(std::ifstream& stream, size_t fileSize, HashResult& outHash) noexcept
	{
		int errorCode = 0;
		crypto_blake2b_ctx context{};
		crypto_blake2b_init(&context, HASHLEN);

		try
		{
			constexpr size_t bufferSize = BLOCKLEN;
			ByteSequence<ByteSequenceTag::TempInternalBuffer, bufferSize> buffer;
			const size_t blockCount = fileSize / bufferSize;
			for (size_t i = 0; i < blockCount; ++i)
			{
				if (!stream.read(reinterpret_cast<char*>(buffer.raw.data()), buffer.raw.size()))
				{
					Debug::Log::printDebug("hashFile function unexpected eof reading block");
					errorCode = -1;
					break;
				}
				hashUpdateDyn_blake2b(&context, buffer);
			}
			const size_t lastBlockSize = (fileSize - blockCount * bufferSize);
			if (lastBlockSize > 0 && errorCode == 0)
			{
				assertFatalRelease(lastBlockSize <= bufferSize, "Logical error, last block size was bigger than the buffer");
				if (!stream.read(reinterpret_cast<char*>(buffer.raw.data()), lastBlockSize))
				{
					Debug::Log::printDebug("hashFile function unexpected eof reading last block");
					errorCode = -1;
				}
				hashUpdateDyn_blake2b(&context, std::span<std::byte>(buffer.raw.data(), lastBlockSize));
			}
		}
		catch (const std::exception& e)
		{
			Debug::Log::printDebug("Exception thrown when trying to compute hash: {}", e.what());
			errorCode = -1;
		}

		hashFinal_blake2b<HASHLEN>(&context, outHash);
		return errorCode;
	}
} // namespace Cryptography
