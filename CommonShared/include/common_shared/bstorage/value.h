// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace BStorage
{
	enum class Tag : uint8_t
	{
		U8 = 0x01,
		U16 = 0x02,
		U32 = 0x03,
		U64 = 0x04,
		String = 0x05,
		ByteArray = 0x06,
		Option = 0x07,
		Array = 0x08,
		Object = 0x09,
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
		[[nodiscard]] static Value makeByteArray(const std::vector<uint8_t>& v) noexcept;
		[[nodiscard]] static Value makeByteArray(std::vector<uint8_t>&& v) noexcept;
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
		std::vector<uint8_t>* asByteArray() noexcept;
		const std::vector<uint8_t>* asByteArray() const noexcept;
		std::unique_ptr<Value>* asOption() noexcept;
		const std::unique_ptr<Value>* asOption() const noexcept;
		std::vector<Value>* asArray() noexcept;
		const std::vector<Value>* asArray() const noexcept;
		std::unordered_map<std::string, Value>* asObject() noexcept;
		const std::unordered_map<std::string, Value>* asObject() const noexcept;

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
			std::vector<uint8_t> ByteArray;
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
