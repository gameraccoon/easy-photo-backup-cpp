// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/bstorage/value.h"

namespace BStorage
{
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

	Value Value::makeByteArray(const std::vector<uint8_t>& v) noexcept
	{
		Value newValue(Tag::ByteArray);
		new (&newValue.mStorage.ByteArray) std::vector<uint8_t>(v);
		return newValue;
	}

	Value Value::makeByteArray(std::vector<uint8_t>&& v) noexcept
	{
		Value newValue(Tag::ByteArray);
		new (&newValue.mStorage.ByteArray) std::vector<uint8_t>(std::move(v));
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
	std::vector<uint8_t>* Value::asByteArray() noexcept
	{
		if (mTag == Tag::ByteArray)
		{
			return &mStorage.ByteArray;
		}
		return nullptr;
	}

	const std::vector<uint8_t>* Value::asByteArray() const noexcept
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
			new (&mStorage.ByteArray) std::vector<uint8_t>(v.mStorage.ByteArray);
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
			new (&mStorage.ByteArray) std::vector<uint8_t>(std::move(v.mStorage.ByteArray));
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
			mStorage.ByteArray.std::vector<uint8_t>::~vector<uint8_t>();
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
