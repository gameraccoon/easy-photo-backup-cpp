// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/client_storage.h"

#include "common_shared/bstorage/storage.h"

namespace ClientStorageInternal
{
	static constexpr uint16_t ClientStorageVersion = 0;
	static const std::string ClientStoragePath = "./client_storage.bin";
	static constexpr std::string ConfirmedField = "confirmed";
	static constexpr std::string NameField = "name";
	static constexpr std::string RemoteStaticKeyField = "rs";
	static constexpr std::string StaticPublicKeyField = "s_pub";
	static constexpr std::string StaticSecretKeyField = "s_secret";

	template<size_t N>
	static void tryConsumeObjectFieldArray(std::unordered_map<std::string, BStorage::Value>& record, const std::string& name, std::array<std::byte, N>& result)
	{
		if (auto it = record.find(name); it != record.end())
		{
			if (std::vector<std::byte>* v = it->second.asByteArray())
			{
				if (v->size() == N)
				{
					std::copy(v->begin(), v->end(), result.begin());
				}
			}
		}
	}

	template<typename T>
	static void tryConsumeObjectField(std::unordered_map<std::string, BStorage::Value>& record, const std::string& name, T& result)
	{
		constexpr auto getT = [](BStorage::Value& v) -> T* {
			if constexpr (std::is_same_v<T, std::string>)
			{
				return v.asString();
			}
			else if constexpr (std::is_same_v<T, std::vector<std::byte>>)
			{
				return v.asByteArray();
			}
			else if constexpr (std::is_same_v<T, uint64_t>)
			{
				return v.asU64();
			}
			else
			{
				static_assert(false, "Unknown type");
			}
		};

		if (auto it = record.find(name); it != record.end())
		{
			if (T* v = getT(it->second))
			{
				result = std::move(*v);
			}
		}
	}

	static BStorage::Value WriteConfirmedServerBindingsToValue(const std::unordered_multimap<std::string, ClientStorageData::ServerBinding>& confirmedServerBindings)
	{
		std::vector<BStorage::Value> vec;
		vec.reserve(confirmedServerBindings.size());
		for (auto& pair : confirmedServerBindings)
		{
			std::unordered_map<std::string, BStorage::Value> record;
			record.reserve(4);
			record.emplace(NameField, BStorage::Value::makeString(pair.first));
			record.emplace(StaticPublicKeyField, BStorage::Value::makeByteArray(std::vector<std::byte>(pair.second.staticKeys.publicKey.raw.begin(), pair.second.staticKeys.publicKey.raw.end())));
			record.emplace(StaticSecretKeyField, BStorage::Value::makeByteArray(std::vector<std::byte>(pair.second.staticKeys.secretKey.raw.begin(), pair.second.staticKeys.secretKey.raw.end())));
			record.emplace(RemoteStaticKeyField, BStorage::Value::makeByteArray(std::vector<std::byte>(pair.second.remoteStaticKey.raw.begin(), pair.second.remoteStaticKey.raw.end())));
			vec.push_back(BStorage::Value::makeObject(std::move(record)));
		}

		return BStorage::Value::makeArray(std::move(vec));
	}

	static void ReadConfirmedServerBindingsToValue(BStorage::Value&& value, std::unordered_multimap<std::string, ClientStorageData::ServerBinding>& confirmedServerBindings)
	{
		if (std::vector<BStorage::Value>* vec = value.asArray())
		{
			confirmedServerBindings.reserve(vec->size());
			for (BStorage::Value& val : *vec)
			{
				if (std::unordered_map<std::string, BStorage::Value>* record = val.asObject())
				{
					ClientStorageData::ServerBinding newItem{};
					std::string name;
					tryConsumeObjectField<std::string>(*record, NameField, name);
					tryConsumeObjectFieldArray(*record, StaticPublicKeyField, newItem.staticKeys.publicKey.raw);
					tryConsumeObjectFieldArray(*record, StaticSecretKeyField, newItem.staticKeys.secretKey.raw);
					tryConsumeObjectFieldArray(*record, RemoteStaticKeyField, newItem.remoteStaticKey.raw);
					confirmedServerBindings.emplace(std::move(name), std::move(newItem));
				}
			}
		}
	}

	static BStorage::Value WriteClientStorageDataToValue(const ClientStorageData& data)
	{
		std::unordered_map<std::string, BStorage::Value> clientStorageDataObject;
		clientStorageDataObject.reserve(2);
		clientStorageDataObject.emplace(
			ConfirmedField,
			WriteConfirmedServerBindingsToValue(data.confirmedServerBindings)
		);
		return BStorage::Value::makeObject(std::move(clientStorageDataObject));
	}

	static ClientStorageData ReadClientStorageDataFromValue(BStorage::Value&& value)
	{
		ClientStorageData result{};
		std::unordered_map<std::string, BStorage::Value>* object = value.asObject();
		if (object != nullptr)
		{
			if (auto it = object->find(ConfirmedField); it != object->end())
			{
				ReadConfirmedServerBindingsToValue(std::move(it->second), result.confirmedServerBindings);
			}
		}
		return result;
	}
} // namespace ClientStorageInternal

ClientStorage ClientStorage::load() noexcept
{
	std::optional<std::tuple<BStorage::Value, uint16_t>> loaded = BStorage::loadStorage(ClientStorageInternal::ClientStoragePath);

	if (loaded.has_value())
	{
		if (std::get<1>(*loaded) != ClientStorageInternal::ClientStorageVersion)
		{
			// here we need to have an update path
			return ClientStorage(BStorage::Value::makeObject({}));
		}

		return ClientStorage(std::get<0>(std::move(*loaded)));
	}
	else
	{
		return ClientStorage(BStorage::Value::makeObject({}));
	}
}

bool ClientStorage::save() const noexcept
{
	using namespace ClientStorageInternal;

	std::lock_guard g(mMutex);
	return BStorage::saveStorage(ClientStoragePath, WriteClientStorageDataToValue(mStorageData), ClientStorageVersion);
}

void ClientStorage::read(const std::function<void(const ClientStorageData&)>& readFn) const noexcept
{
	std::lock_guard g(mMutex);
	readFn(mStorageData);
}

void ClientStorage::mutate(const std::function<void(ClientStorageData&)>& mutateFn) noexcept
{
	std::lock_guard g(mMutex);
	mutateFn(mStorageData);
}

ClientStorage::ClientStorage(BStorage::Value&& value) noexcept
	: mStorageData(ClientStorageInternal::ReadClientStorageDataFromValue(std::move(value)))
{
}
