// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/bstorage/value.h"

#include <array>

namespace BStorage
{
	namespace Internal
	{
		enum class TagBits : uint8_t
		{
			DynamicUnknown = 0x00,

			// fixed size
			U8 = 0x10,
			U16 = 0x20,
			U32 = 0x30,
			U64 = 0x40,

			// variable size
			String = 0x01,
			ByteArray = 0x11,

			// compound, recursive
			OptionNull = 0x02,
			OptionSet = 0x12,

			ArrayEmpty = 0x03,
			ArrayVariableTypes = 0x13,
			ArraySameType = 0x23, // does not repeat the type for each element

			Object = 0x04,
		};

		TagBits getAssociatedTagBits(Tag tag)
		{
			switch (tag)
			{
			case Tag::U8:
				return TagBits::U8;
			case Tag::U16:
				return TagBits::U16;
			case Tag::U32:
				return TagBits::U32;
			case Tag::U64:
				return TagBits::U64;
			case Tag::String:
				return TagBits::String;
			case Tag::ByteArray:
				return TagBits::ByteArray;
			case Tag::Option:
				return TagBits::DynamicUnknown;
			case Tag::Array:
				return TagBits::DynamicUnknown;
			case Tag::Object:
				return TagBits::Object;
			}

			// unreachable, but GCC does not believe that
			return TagBits::DynamicUnknown;
		}

		template<typename T>
		void writeUint(std::ostream& outputStream, T v)
		{
			if constexpr (sizeof(v) == 1)
			{
				// ReSharper disable once CppDFAUnreachableCode
				outputStream.write(std::bit_cast<const char*>(&v), sizeof(v));
			}
			else if constexpr (std::endian::native == std::endian::big)
			{
				// ReSharper disable once CppDFAUnreachableCode
				outputStream.write(std::bit_cast<const char*>(&v), sizeof(v));
			}
			else
			{
				// ReSharper disable once CppDFAUnreachableCode
				std::array<char, sizeof(T)> temp = {};
				for (size_t i = 0; i < sizeof(T); ++i)
				{
					temp[i] = (v >> ((sizeof(T) - (i + 1)) * 8)) & 0xFF;
				}
				outputStream.write(temp.data(), temp.size());
			}
		}

		template<typename T>
		[[nodiscard]] T readUint(std::istream& inputStream)
		{
			T v = 0;
			if constexpr (sizeof(v) == 1)
			{
				// ReSharper disable once CppDFAUnreachableCode
				inputStream.read(std::bit_cast<char*>(&v), sizeof(v));
			}
			else if constexpr (std::endian::native == std::endian::big)
			{
				// ReSharper disable once CppDFAUnreachableCode
				inputStream.read(std::bit_cast<char*>(&v), sizeof(v));
			}
			else
			{
				// ReSharper disable once CppDFAUnreachableCode
				std::array<char, sizeof(T)> temp = {};
				inputStream.read(temp.data(), temp.size());
				for (size_t i = 0; i < sizeof(T); ++i)
				{
					v |= temp[i] << ((sizeof(T) - (i + 1)) * 8);
				}
			}

			return v;
		}

		constexpr size_t MaxContainerSize = 0x3FFFFFFF;

		void writeSize(std::ostream& outputStream, size_t size)
		{
			// most arrays are within 127 elements
			if (size <= 0x7F)
			{
				writeUint<uint8_t>(outputStream, static_cast<uint8_t>(size));
				return;
			}

			// and very rarely above 16383 elements
			if (size <= 0x3FFF)
			{
				// make space for the bit to signal about 2 bit value
				const uint16_t bitRepresentation = 0x8000 | ((size & 0x3F80) << 1) | (size & 0x7F);
				writeUint<uint16_t>(outputStream, bitRepresentation);
				return;
			}

			// and if we get value above 1073741823, we treat it as incorrect with MaxContainerSize
			const uint32_t bitRepresentation = 0x80800000 | ((size & 0x3F800000) << 1) | (size & 0x7FFFFF);
			writeUint<uint32_t>(outputStream, bitRepresentation);
		}

		size_t readSize(std::istream& inputStream)
		{
			const size_t firstByte = readUint<uint8_t>(inputStream);

			// no first bit set means the value is within 0x7F
			if ((firstByte & 0x80) == 0)
			{
				return firstByte;
			}

			const size_t secondByte = readUint<uint8_t>(inputStream);
			if ((secondByte & 0x80) == 0)
			{
				return ((firstByte & 0x7F) << 7) | secondByte;
			}

			const size_t lastBytes = readUint<uint16_t>(inputStream);
			return ((firstByte & 0x7F) << 23) | ((secondByte & 0x7F) << 16) | lastBytes;
		}
	} // namespace Internal

	Value Value::makeU8(uint8_t v) noexcept
	{
		Value newValue(Tag::U8);
		newValue.mStorage.U8 = v;
		return newValue;
	}

	Value Value::makeU16(uint16_t v) noexcept
	{
		Value newValue(Tag::U16);
		newValue.mStorage.U16 = v;
		return newValue;
	}

	Value Value::makeU32(uint32_t v) noexcept
	{
		Value newValue(Tag::U32);
		newValue.mStorage.U32 = v;
		return newValue;
	}

	Value Value::makeU64(uint64_t v) noexcept
	{
		Value newValue(Tag::U64);
		newValue.mStorage.U64 = v;
		return newValue;
	}

	Value Value::makeString(const std::string& v) noexcept
	{
		Value newValue(Tag::String);
		new (&newValue.mStorage.String) std::string(v);
		return newValue;
	}

	Value Value::makeString(std::string&& v) noexcept
	{
		Value newValue(Tag::String);
		new (&newValue.mStorage.String) std::string(std::move(v));
		return newValue;
	}

	Value Value::makeByteArray(const std::vector<std::byte>& v) noexcept
	{
		Value newValue(Tag::ByteArray);
		new (&newValue.mStorage.ByteArray) std::vector<std::byte>(v);
		return newValue;
	}

	Value Value::makeByteArray(std::vector<std::byte>&& v) noexcept
	{
		Value newValue(Tag::ByteArray);
		new (&newValue.mStorage.ByteArray) std::vector<std::byte>(std::move(v));
		return newValue;
	}

	Value Value::makeOption(const std::unique_ptr<Value>& v) noexcept
	{
		Value newValue(Tag::Option);
		if (v)
		{
			new (&newValue.mStorage.Option) std::unique_ptr<Value>(new Value(*v));
		}
		else
		{
			new (&newValue.mStorage.Option) std::unique_ptr<Value>();
		}
		return newValue;
	}

	Value Value::makeOption(std::unique_ptr<Value>&& v) noexcept
	{
		Value newValue(Tag::Option);
		new (&newValue.mStorage.Option) std::unique_ptr<Value>(std::move(v));
		return newValue;
	}

	Value Value::makeArray(const std::vector<Value>& v) noexcept
	{
		Value newValue(Tag::Array);
		new (&newValue.mStorage.Array) std::vector<Value>(v);
		return newValue;
	}

	Value Value::makeArray(std::vector<Value>&& v) noexcept
	{
		Value newValue(Tag::Array);
		new (&newValue.mStorage.Array) std::vector<Value>(std::move(v));
		return newValue;
	}

	Value Value::makeObject(const std::unordered_map<std::string, Value>& v) noexcept
	{
		Value newValue(Tag::Object);
		new (&newValue.mStorage.Object) std::unordered_map<std::string, Value>(v);
		return newValue;
	}

	Value Value::makeObject(std::unordered_map<std::string, Value>&& v) noexcept
	{
		Value newValue(Tag::Object);
		new (&newValue.mStorage.Object) std::unordered_map<std::string, Value>(std::move(v));
		return newValue;
	}

	uint8_t* Value::asU8() noexcept
	{
		if (mTag == Tag::U8)
		{
			return &mStorage.U8;
		}
		return nullptr;
	}

	const uint8_t* Value::asU8() const noexcept
	{
		if (mTag == Tag::U8)
		{
			return &mStorage.U8;
		}
		return nullptr;
	}

	uint16_t* Value::asU16() noexcept
	{
		if (mTag == Tag::U16)
		{
			return &mStorage.U16;
		}
		return nullptr;
	}

	const uint16_t* Value::asU16() const noexcept
	{
		if (mTag == Tag::U16)
		{
			return &mStorage.U16;
		}
		return nullptr;
	}

	uint32_t* Value::asU32() noexcept
	{
		if (mTag == Tag::U32)
		{
			return &mStorage.U32;
		}
		return nullptr;
	}

	const uint32_t* Value::asU32() const noexcept
	{
		if (mTag == Tag::U32)
		{
			return &mStorage.U32;
		}
		return nullptr;
	}

	uint64_t* Value::asU64() noexcept
	{
		if (mTag == Tag::U64)
		{
			return &mStorage.U64;
		}
		return nullptr;
	}

	const uint64_t* Value::asU64() const noexcept
	{
		if (mTag == Tag::U64)
		{
			return &mStorage.U64;
		}
		return nullptr;
	}

	std::string* Value::asString() noexcept
	{
		if (mTag == Tag::String)
		{
			return &mStorage.String;
		}
		return nullptr;
	}

	const std::string* Value::asString() const noexcept
	{
		if (mTag == Tag::String)
		{
			return &mStorage.String;
		}
		return nullptr;
	}
	std::vector<std::byte>* Value::asByteArray() noexcept
	{
		if (mTag == Tag::ByteArray)
		{
			return &mStorage.ByteArray;
		}
		return nullptr;
	}

	const std::vector<std::byte>* Value::asByteArray() const noexcept
	{
		if (mTag == Tag::ByteArray)
		{
			return &mStorage.ByteArray;
		}
		return nullptr;
	}

	std::unique_ptr<Value>* Value::asOption() noexcept
	{
		if (mTag == Tag::Option)
		{
			return &mStorage.Option;
		}
		return nullptr;
	}

	const std::unique_ptr<Value>* Value::asOption() const noexcept
	{
		if (mTag == Tag::Option)
		{
			return &mStorage.Option;
		}
		return nullptr;
	}

	std::vector<Value>* Value::asArray() noexcept
	{
		if (mTag == Tag::Array)
		{
			return &mStorage.Array;
		}
		return nullptr;
	}

	const std::vector<Value>* Value::asArray() const noexcept
	{
		if (mTag == Tag::Array)
		{
			return &mStorage.Array;
		}
		return nullptr;
	}

	std::unordered_map<std::string, Value>* Value::asObject() noexcept
	{
		if (mTag == Tag::Object)
		{
			return &mStorage.Object;
		}
		return nullptr;
	}

	const std::unordered_map<std::string, Value>* Value::asObject() const noexcept
	{
		if (mTag == Tag::Object)
		{
			return &mStorage.Object;
		}
		return nullptr;
	}

	bool Value::writeToStream(std::ostream& outputStream, bool skipTag) const noexcept
	{
		const Internal::TagBits tagBits = Internal::getAssociatedTagBits(mTag);
		if (skipTag && tagBits == Internal::TagBits::DynamicUnknown)
		{
			// can't skip tag bits that are based on the content
			return false;
		}

		if (!skipTag && tagBits != Internal::TagBits::DynamicUnknown)
		{
			Internal::writeUint<uint8_t>(outputStream, static_cast<uint8_t>(tagBits));
		}

		switch (mTag)
		{
		case Tag::U8:
			Internal::writeUint<uint8_t>(outputStream, mStorage.U8);
			return true;
		case Tag::U16:
			Internal::writeUint<uint16_t>(outputStream, mStorage.U16);
			return true;
		case Tag::U32:
			Internal::writeUint<uint32_t>(outputStream, mStorage.U32);
			return true;
		case Tag::U64:
			Internal::writeUint<uint64_t>(outputStream, mStorage.U64);
			return true;
		case Tag::String: {
			if (mStorage.String.size() > Internal::MaxContainerSize)
			{
				return false;
			}
			Internal::writeSize(outputStream, mStorage.String.size());
			outputStream.write(mStorage.String.data(), mStorage.String.size());
			return true;
		}
		case Tag::ByteArray: {
			if (mStorage.ByteArray.size() > Internal::MaxContainerSize)
			{
				return false;
			}
			Internal::writeSize(outputStream, mStorage.ByteArray.size());
			outputStream.write(std::bit_cast<char*>(mStorage.ByteArray.data()), mStorage.ByteArray.size());
			return true;
		}
		case Tag::Option: {
			if (mStorage.Option)
			{
				Internal::writeUint<uint8_t>(outputStream, static_cast<uint8_t>(Internal::TagBits::OptionSet));
				return mStorage.Option->writeToStream(outputStream);
			}
			else
			{
				Internal::writeUint<uint8_t>(outputStream, static_cast<uint8_t>(Internal::TagBits::OptionNull));
				return true;
			}
		}
		case Tag::Array: {
			if (mStorage.Array.size() > Internal::MaxContainerSize)
			{
				return false;
			}

			if (mStorage.Array.empty())
			{
				Internal::writeUint<uint8_t>(outputStream, static_cast<uint8_t>(Internal::TagBits::ArrayEmpty));
				return true;
			}

			bool allAreSameType = true;
			const Tag firstTag = mStorage.Array.front().mTag;
			const Internal::TagBits firstTagBits = Internal::getAssociatedTagBits(firstTag);
			if (firstTagBits == Internal::TagBits::DynamicUnknown)
			{
				// some types can have different tags based on data
				// and we don't want to recursively inspect them here
				allAreSameType = false;
			}
			else
			{
				for (size_t i = 1; i < mStorage.Array.size(); ++i)
				{
					if (mStorage.Array[i].mTag != firstTag)
					{
						allAreSameType = false;
						break;
					}
				}
			}

			if (allAreSameType)
			{
				Internal::writeUint<uint8_t>(outputStream, static_cast<uint8_t>(Internal::TagBits::ArraySameType));
				Internal::writeSize(outputStream, mStorage.Array.size());
				Internal::writeUint<uint8_t>(outputStream, static_cast<uint8_t>(firstTagBits));
				for (const Value& v : mStorage.Array)
				{
					if (v.writeToStream(outputStream, true) == false)
					{
						return false;
					}
				}
			}
			else
			{
				Internal::writeUint<uint8_t>(outputStream, static_cast<uint8_t>(Internal::TagBits::ArrayVariableTypes));
				Internal::writeSize(outputStream, mStorage.Array.size());
				for (const Value& v : mStorage.Array)
				{
					if (v.writeToStream(outputStream) == false)
					{
						return false;
					}
				}
			}
			return true;
		}
		case Tag::Object: {
			if (mStorage.Object.size() > Internal::MaxContainerSize)
			{
				return false;
			}
			Internal::writeSize(outputStream, mStorage.Object.size());
			for (const std::pair<const std::string, Value>& pair : mStorage.Object)
			{
				if (pair.first.size() > Internal::MaxContainerSize)
				{
					return false;
				}
				Internal::writeSize(outputStream, pair.first.size());
				outputStream.write(pair.first.data(), pair.first.size());

				if (pair.second.writeToStream(outputStream) == false)
				{
					return false;
				}
			}
			return true;
		}
		}

		// unreachable, but GCC does not believe that
		return false;
	}

	std::optional<Value> Value::readFromStream(std::istream& inputStream, std::optional<uint8_t> forcedTag) noexcept
	{
		uint8_t tagBits;
		if (forcedTag.has_value())
		{
			tagBits = *forcedTag;
		}
		else
		{
			tagBits = Internal::readUint<uint8_t>(inputStream);
		}

		switch (tagBits)
		{
		case static_cast<uint8_t>(Internal::TagBits::U8):
			return makeU8(Internal::readUint<uint8_t>(inputStream));
		case static_cast<uint8_t>(Internal::TagBits::U16):
			return makeU16(Internal::readUint<uint16_t>(inputStream));
		case static_cast<uint8_t>(Internal::TagBits::U32):
			return makeU32(Internal::readUint<uint32_t>(inputStream));
		case static_cast<uint8_t>(Internal::TagBits::U64):
			return makeU64(Internal::readUint<uint64_t>(inputStream));
		case static_cast<uint8_t>(Internal::TagBits::String): {
			const size_t size = Internal::readSize(inputStream);
			std::string result;
			result.resize(size);
			inputStream.read(result.data(), result.size());
			return makeString(std::move(result));
		}
		case static_cast<uint8_t>(Internal::TagBits::ByteArray): {
			const size_t size = Internal::readSize(inputStream);
			std::vector<std::byte> result;
			result.resize(size);
			inputStream.read(std::bit_cast<char*>(result.data()), result.size());
			return makeByteArray(std::move(result));
		}
		case static_cast<uint8_t>(Internal::TagBits::OptionNull):
			return makeOption(std::unique_ptr<Value>{});
		case static_cast<uint8_t>(Internal::TagBits::OptionSet): {
			std::optional<Value> internalValue = readFromStream(inputStream);
			if (internalValue.has_value())
			{
				return makeOption(std::make_unique<Value>(std::move(*internalValue)));
			}
			else
			{
				return std::nullopt;
			}
		}
		case static_cast<uint8_t>(Internal::TagBits::ArrayEmpty):
			return makeArray(std::vector<Value>{});
		case static_cast<uint8_t>(Internal::TagBits::ArraySameType): {
			const size_t size = Internal::readSize(inputStream);
			const uint8_t valueTag = Internal::readUint<uint8_t>(inputStream);
			std::vector<Value> result;
			result.reserve(size);
			for (size_t i = 0; i < size; ++i)
			{
				std::optional<Value> internalValue = readFromStream(inputStream, valueTag);
				if (internalValue.has_value())
				{
					result.push_back(std::move(*internalValue));
				}
				else
				{
					return std::nullopt;
				}
			}

			return makeArray(std::move(result));
		}
		case static_cast<uint8_t>(Internal::TagBits::ArrayVariableTypes): {
			const size_t size = Internal::readSize(inputStream);
			std::vector<Value> result;
			result.reserve(size);
			for (size_t i = 0; i < size; ++i)
			{
				std::optional<Value> internalValue = readFromStream(inputStream);
				if (internalValue.has_value())
				{
					result.push_back(std::move(*internalValue));
				}
				else
				{
					return std::nullopt;
				}
			}

			return makeArray(std::move(result));
		}
		case static_cast<uint8_t>(Internal::TagBits::Object): {
			const size_t size = Internal::readSize(inputStream);
			std::unordered_map<std::string, Value> result;
			result.reserve(size);
			for (size_t i = 0; i < size; ++i)
			{
				const uint16_t size = Internal::readSize(inputStream);
				std::string key;
				key.resize(size);
				inputStream.read(key.data(), key.size());

				std::optional<Value> internalValue = readFromStream(inputStream);
				if (internalValue.has_value())
				{
					result.emplace(std::move(key), std::move(*internalValue));
				}
				else
				{
					return std::nullopt;
				}
			}

			return makeObject(std::move(result));
		}
		}

		return std::nullopt;
	}

	[[nodiscard]] bool Value::isSameDeepCompare(const Value& other) const
	{
		if (mTag != other.mTag)
		{
			return false;
		}

		switch (mTag)
		{
		case Tag::U8:
			return mStorage.U8 == other.mStorage.U8;
		case Tag::U16:
			return mStorage.U16 == other.mStorage.U16;
		case Tag::U32:
			return mStorage.U32 == other.mStorage.U32;
		case Tag::U64:
			return mStorage.U64 == other.mStorage.U64;
		case Tag::String: {
			return mStorage.String == other.mStorage.String;
		}
		case Tag::ByteArray: {
			return mStorage.ByteArray == other.mStorage.ByteArray;
		}
		case Tag::Option: {
			if ((mStorage.Option == nullptr) != (other.mStorage.Option == nullptr))
			{
				return false;
			}
			else if (mStorage.Option == nullptr)
			{
				return true;
			}
			else
			{
				return mStorage.Option->isSameDeepCompare(*other.mStorage.Option);
			}
			break;
		}
		case Tag::Array: {
			if (mStorage.Array.size() != other.mStorage.Array.size())
			{
				return false;
			}

			for (size_t i = 0; i < mStorage.Array.size(); ++i)
			{
				if (!mStorage.Array[i].isSameDeepCompare(other.mStorage.Array[i]))
				{
					return false;
				}
			}
			return true;
			break;
		}
		case Tag::Object: {
			if (mStorage.Object.size() != other.mStorage.Object.size())
			{
				return false;
			}

			for (const std::pair<const std::string, Value>& pair : mStorage.Object)
			{
				const auto& otherValueIt = other.mStorage.Object.find(pair.first);
				if (otherValueIt == other.mStorage.Object.end())
				{
					return false;
				}

				if (!pair.second.isSameDeepCompare(otherValueIt->second))
				{
					return false;
				}
			}
			return true;
			break;
		}
		}

		// unreachable, but GCC does not believe that
		return false;
	}

	Value::Value(const Value& v) noexcept
		: mTag(v.mTag)
		, mStorage() // uninitialized
	{
		switch (v.mTag)
		{
		case Tag::U8:
			mStorage.U8 = v.mStorage.U8;
			break;
		case Tag::U16:
			mStorage.U16 = v.mStorage.U16;
			break;
		case Tag::U32:
			mStorage.U32 = v.mStorage.U32;
			break;
		case Tag::U64:
			mStorage.U64 = v.mStorage.U64;
			break;
		case Tag::String: {
			new (&mStorage.String) std::string(v.mStorage.String);
			break;
		}
		case Tag::ByteArray: {
			new (&mStorage.ByteArray) std::vector<std::byte>(v.mStorage.ByteArray);
			break;
		}
		case Tag::Option: {
			if (v.mStorage.Option)
			{
				new (&mStorage.Option) std::unique_ptr<Value>(new Value(*v.mStorage.Option));
			}
			else
			{
				new (&mStorage.Option) std::unique_ptr<Value>();
			}
			break;
		}
		case Tag::Array: {
			new (&mStorage.Array) std::vector<Value>(v.mStorage.Array);
			break;
		}
		case Tag::Object: {
			new (&mStorage.Object) std::unordered_map<std::string, Value>(v.mStorage.Object);
			break;
		}
		}
	}

	Value::Value(Value&& v) noexcept
		: mTag(v.mTag)
		, mStorage() // uninitialized
	{
		switch (v.mTag)
		{
		case Tag::U8:
			mStorage.U8 = v.mStorage.U8;
			break;
		case Tag::U16:
			mStorage.U16 = v.mStorage.U16;
			break;
		case Tag::U32:
			mStorage.U32 = v.mStorage.U32;
			break;
		case Tag::U64:
			mStorage.U64 = v.mStorage.U64;
			break;
		case Tag::String: {
			new (&mStorage.String) std::string(std::move(v.mStorage.String));
			break;
		}
		case Tag::ByteArray: {
			new (&mStorage.ByteArray) std::vector<std::byte>(std::move(v.mStorage.ByteArray));
			break;
		}
		case Tag::Option: {
			new (&mStorage.Option) std::unique_ptr<Value>(std::move(v.mStorage.Option));
			break;
		}
		case Tag::Array: {
			new (&mStorage.Array) std::vector<Value>(std::move(v.mStorage.Array));
			break;
		}
		case Tag::Object: {
			new (&mStorage.Object) std::unordered_map<std::string, Value>(std::move(v.mStorage.Object));
			break;
		}
		}
	}

	Value::~Value() noexcept
	{
		switch (mTag)
		{
		case Tag::U8:
		case Tag::U16:
		case Tag::U32:
		case Tag::U64:
			// no need to do anything for trivial types
			break;
		case Tag::String: {
			mStorage.String.std::string::~string();
			break;
		}
		case Tag::ByteArray: {
			mStorage.ByteArray.std::vector<std::byte>::~vector<std::byte>();
			break;
		}
		case Tag::Option: {
			mStorage.Option.std::unique_ptr<Value>::~unique_ptr<Value>();
			break;
		}
		case Tag::Array: {
			mStorage.Array.std::vector<Value>::~vector<Value>();
			break;
		}
		case Tag::Object: {
			mStorage.Object.std::unordered_map<std::string, Value>::~unordered_map<std::string, Value>();
			break;
		}
		}
	}

	Value::Value(Tag tag)
		: mTag(tag)
		, mStorage() // left uninitialized
	{
	}

	Value::Storage::Storage() noexcept
	{
		// do nothing as the proper construction is handled in the make* functions
	}

	Value::Storage::~Storage() noexcept
	{
		// do nothing as the proper destruction is handled in Value destructor
	}
} // namespace BStorage
