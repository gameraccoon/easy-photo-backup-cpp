// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace Cryptography
{
	// we plan to use this data for very speicific needs, and don't want to mix those needs
	enum class Tag
	{
		PublicKey,
		SecretKey,
		DhResult,
		HashResult,
		CipherKey,
		Nonce,
		TempInternalBuffer,
	};

	void cryptoWipeRawData(std::span<uint8_t> rawData);

	template<Tag, std::size_t DataLen>
	struct ByteSequence
	{
		std::array<uint8_t, DataLen> raw = {};

		ByteSequence() noexcept = default;

		// allow the byte sequence being passed as a span
		operator std::span<uint8_t>() noexcept { return raw; }
		operator std::span<const uint8_t>() const noexcept { return raw; }
		constexpr size_t size() const noexcept { return raw.size(); }

		ByteSequence clone() const noexcept { return ByteSequence{ raw }; }

		// rule of five, no implicit copy, allow move, require secure erase of each copy
		ByteSequence(const ByteSequence&) noexcept = delete;
		ByteSequence(ByteSequence&&) noexcept = default;
		ByteSequence& operator=(const ByteSequence&) noexcept = delete;
		ByteSequence& operator=(ByteSequence&&) noexcept = default;
		~ByteSequence() noexcept { cryptoWipeRawData(raw); }

	private:
		explicit ByteSequence(const std::array<uint8_t, DataLen>& data) noexcept
			: raw(data) {}
	};

	// note that growing the buffer while already filled with data will not securely erase the old buffer
	struct DynByteSequence
	{
		std::vector<uint8_t> raw;

		DynByteSequence() noexcept = default;

		// note that the data in the source container need to be erased as well
		static DynByteSequence fromVector(std::vector<uint8_t>&& data) noexcept { return DynByteSequence(std::move(data)); }

		// allow the byte sequence being passed as a span
		operator std::span<uint8_t>() noexcept { return raw; }
		operator std::span<const uint8_t>() const noexcept { return raw; }
		constexpr size_t size() const noexcept { return raw.size(); }

		DynByteSequence clone() const noexcept { return DynByteSequence{ raw }; }

		void clearResize(const size_t newSize) noexcept
		{
			// make sure we are clearing the previous buffer before reallocating
			cryptoWipeRawData(raw);
			raw.resize(newSize);
		}

		// rule of five, no implicit copy, allow move, require secure erase of each copy
		DynByteSequence(const DynByteSequence&) noexcept = delete;
		DynByteSequence(DynByteSequence&&) noexcept = default;
		DynByteSequence& operator=(const DynByteSequence&) noexcept = delete;
		DynByteSequence& operator=(DynByteSequence&&) noexcept = default;
		~DynByteSequence() noexcept { cryptoWipeRawData(raw); }

	private:
		explicit DynByteSequence(std::vector<uint8_t>&& data) noexcept
			: raw(std::move(data)) {}

		explicit DynByteSequence(const std::span<const uint8_t> data) noexcept
			: raw(data.begin(), data.end()) {}
	};
} // namespace Cryptography
