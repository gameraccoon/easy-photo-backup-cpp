// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).
#pragma once

#include <cstdint>
#include <istream>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace BStorage
{
	enum class Tag : uint8_t
	{
		U8,
		U16,
		U32,
		U64,
		String,
		ByteArray,
		Option,
		Array,
		Object,
	};

	class Value
	{
	public:
		[[nodiscard]] static Value makeU8(uint8_t v) noexcept;
		[[nodiscard]] static Value makeU16(uint16_t v) noexcept;
		[[nodiscard]] static Value makeU32(uint32_t v) noexcept;
		[[nodiscard]] static Value makeU64(uint64_t v) noexcept;
		[[nodiscard]] static Value makeString(const std::string& v) noexcept;
		[[nodiscard]] static Value makeString(std::string&& v) noexcept;
		[[nodiscard]] static Value makeByteArray(const std::vector<std::byte>& v) noexcept;
		[[nodiscard]] static Value makeByteArray(std::vector<std::byte>&& v) noexcept;
		[[nodiscard]] static Value makeOption(const std::unique_ptr<Value>& v) noexcept;
		[[nodiscard]] static Value makeOption(std::unique_ptr<Value>&& v) noexcept;
		[[nodiscard]] static Value makeArray(const std::vector<Value>& v) noexcept;
		[[nodiscard]] static Value makeArray(std::vector<Value>&& v) noexcept;
		[[nodiscard]] static Value makeObject(const std::unordered_map<std::string, Value>& v) noexcept;
		[[nodiscard]] static Value makeObject(std::unordered_map<std::string, Value>&& v) noexcept;

		bool isA(Tag tag) const { return mTag == tag; }

		uint8_t* asU8() noexcept;
		const uint8_t* asU8() const noexcept;
		uint16_t* asU16() noexcept;
		const uint16_t* asU16() const noexcept;
		uint32_t* asU32() noexcept;
		const uint32_t* asU32() const noexcept;
		uint64_t* asU64() noexcept;
		const uint64_t* asU64() const noexcept;
		std::string* asString() noexcept;
		const std::string* asString() const noexcept;
		std::vector<std::byte>* asByteArray() noexcept;
		const std::vector<std::byte>* asByteArray() const noexcept;
		std::unique_ptr<Value>* asOption() noexcept;
		const std::unique_ptr<Value>* asOption() const noexcept;
		std::vector<Value>* asArray() noexcept;
		const std::vector<Value>* asArray() const noexcept;
		std::unordered_map<std::string, Value>* asObject() noexcept;
		const std::unordered_map<std::string, Value>* asObject() const noexcept;

		// sure, these are not the most optimal, but it should do for now
		[[nodiscard]] bool writeToStream(std::ostream& outputStream, bool skipTag = false) const noexcept;
		[[nodiscard]] static std::optional<Value> readFromStream(std::istream& inputStream, std::optional<uint8_t> forcedTag = {}) noexcept;

		[[nodiscard]] bool isSameDeepCompare(const Value& other) const;

		Value(const Value&) noexcept;
		Value& operator=(const Value&) noexcept = delete;
		Value(Value&&) noexcept;
		Value& operator=(Value&&) noexcept = delete;
		~Value() noexcept;

	private:
		union Storage
		{
			uint8_t U8;
			uint16_t U16;
			uint32_t U32;
			uint64_t U64;
			std::string String;
			std::vector<std::byte> ByteArray;
			std::unique_ptr<Value> Option;
			std::vector<Value> Array;
			std::unordered_map<std::string, Value> Object;

			Storage() noexcept;
			Storage(const Storage&) noexcept = delete;
			Storage(Storage&&) noexcept = delete;
			Storage& operator=(const Storage&) noexcept = delete;
			Storage& operator=(Storage&&) noexcept = delete;
			~Storage() noexcept;
		};

	private:
		Value(Tag tag);

	private:
		Tag mTag;
		Storage mStorage;
	};
} // namespace BStorage
