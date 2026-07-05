// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/client_storage.h"

#include <string_view>

#include "common_shared/bstorage/storage.h"

namespace ClientStorageInternal
{
	static constexpr uint16_t ClientStorageVersion = 0;
	static constexpr std::string_view ClientStorageFileName = "client_storage.bin";
	static constexpr std::string_view ConfirmedField = "confirmed";
	static constexpr std::string_view SentFilesField = "sent_files";
	static constexpr std::string_view PartiallySentFilesField = "part_sent";
	static constexpr std::string_view ServerIdField = "server_id";
	static constexpr std::string_view NameField = "name";
	static constexpr std::string_view ConnectionIdField = "id";
	static constexpr std::string_view RemoteStaticKeyField = "rs";
	static constexpr std::string_view StaticPublicKeyField = "s_pub";
	static constexpr std::string_view StaticSecretKeyField = "s_secret";
	static constexpr std::string_view FilePathField = "path";
	static constexpr std::string_view SentBytesField = "bytes";

	template<size_t N>
	static void tryConsumeObjectFieldArray(BStorage::Value::ObjectMap& record, const std::string_view name, std::array<std::byte, N>& result)
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
	static void tryConsumeObjectField(BStorage::Value::ObjectMap& record, const std::string_view name, T& result)
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

	static BStorage::Value WriteConfirmedServerBindingsToValue(const ClientStorageData::ConfirmedServerBindingsType& confirmedServerBindings)
	{
		std::vector<BStorage::Value> vec;
		vec.reserve(confirmedServerBindings.size());
		for (auto& pair : confirmedServerBindings)
		{
			BStorage::Value::ObjectMap record;
			record.reserve(4);
			record.emplace(ConnectionIdField, BStorage::Value::makeByteArray(pair.second.connectionId));
			record.emplace(ServerIdField, BStorage::Value::makeByteArray(pair.first));
			record.emplace(NameField, BStorage::Value::makeString(pair.second.serverName));
			record.emplace(StaticPublicKeyField, BStorage::Value::makeByteArray(pair.second.staticKeys.publicKey));
			record.emplace(StaticSecretKeyField, BStorage::Value::makeByteArray(pair.second.staticKeys.secretKey.raw));
			record.emplace(RemoteStaticKeyField, BStorage::Value::makeByteArray(pair.second.remoteStaticKey.raw));
			vec.push_back(BStorage::Value::makeObject(std::move(record)));
		}

		return BStorage::Value::makeArray(std::move(vec));
	}

	static void ReadConfirmedServerBindingsFromValue(BStorage::Value&& value, ClientStorageData::ConfirmedServerBindingsType& confirmedServerBindings)
	{
		if (std::vector<BStorage::Value>* vec = value.asArray())
		{
			confirmedServerBindings.reserve(vec->size());
			for (BStorage::Value& val : *vec)
			{
				if (BStorage::Value::ObjectMap* record = val.asObject())
				{
					ClientStorageData::ServerBinding newItem{};
					ClientStorageData::ServerId serverId{};
					tryConsumeObjectFieldArray(*record, ServerIdField, serverId);
					tryConsumeObjectFieldArray(*record, ConnectionIdField, newItem.connectionId.raw);
					tryConsumeObjectField<std::string>(*record, NameField, newItem.serverName);
					tryConsumeObjectFieldArray(*record, StaticPublicKeyField, newItem.staticKeys.publicKey.raw);
					tryConsumeObjectFieldArray(*record, StaticSecretKeyField, newItem.staticKeys.secretKey.raw);
					tryConsumeObjectFieldArray(*record, RemoteStaticKeyField, newItem.remoteStaticKey.raw);
					confirmedServerBindings.emplace(std::move(serverId), std::move(newItem));
				}
			}
		}
	}

	static BStorage::Value WriteSentFilesToValue(const std::unordered_set<std::string>& sentFiles)
	{
		std::vector<BStorage::Value> vec;
		vec.reserve(sentFiles.size());
		for (const std::string& pair : sentFiles)
		{
			vec.push_back(BStorage::Value::makeString(pair));
		}

		return BStorage::Value::makeArray(std::move(vec));
	}

	static void ReadSentFilesFromValue(BStorage::Value&& value, std::unordered_set<std::string>& sentFiles)
	{
		if (std::vector<BStorage::Value>* vec = value.asArray())
		{
			sentFiles.reserve(vec->size());
			for (BStorage::Value& val : *vec)
			{
				if (std::string* record = val.asString())
				{
					sentFiles.emplace(std::move(*record));
				}
			}
		}
	}

	static BStorage::Value WritePartiallySentFilesToValue(const std::unordered_map<std::string, uint64_t>& partiallySentFiles)
	{
		std::vector<BStorage::Value> vec;
		vec.reserve(partiallySentFiles.size());
		for (auto it = partiallySentFiles.begin(); it != partiallySentFiles.end(); ++it)
		{
			BStorage::Value::ObjectMap partiallySentFileObject;
			partiallySentFileObject.emplace(FilePathField, BStorage::Value::makeString(it->first));
			partiallySentFileObject.emplace(SentBytesField, BStorage::Value::makeU64(it->second));
			vec.push_back(BStorage::Value::makeObject(std::move(partiallySentFileObject)));
		}

		return BStorage::Value::makeArray(std::move(vec));
	}

	static void ReadPartiallySentFilesFromValue(BStorage::Value&& value, std::unordered_map<std::string, uint64_t>& partiallySentFiles)
	{
		if (std::vector<BStorage::Value>* vec = value.asArray())
		{
			partiallySentFiles.reserve(vec->size());
			for (BStorage::Value& val : *vec)
			{
				if (BStorage::Value::ObjectMap* record = val.asObject())
				{
					std::string path;
					uint64_t bytesSent = 0;
					tryConsumeObjectField<std::string>(*record, FilePathField, path);
					tryConsumeObjectField<uint64_t>(*record, SentBytesField, bytesSent);
					partiallySentFiles.emplace(std::move(path), bytesSent);
				}
			}
		}
	}

	static BStorage::Value WriteClientStorageDataToValue(const ClientStorageData& storageData)
	{
		BStorage::Value::ObjectMap clientStorageDataObject;
		clientStorageDataObject.reserve(2);
		clientStorageDataObject.emplace(
			ConfirmedField,
			WriteConfirmedServerBindingsToValue(storageData.confirmedServerBindings)
		);
		clientStorageDataObject.emplace(
			SentFilesField,
			WriteSentFilesToValue(storageData.sentFiles)
		);
		clientStorageDataObject.emplace(
			PartiallySentFilesField,
			WritePartiallySentFilesToValue(storageData.partiallySentFiles)
		);
		return BStorage::Value::makeObject(std::move(clientStorageDataObject));
	}

	static ClientStorageData ReadClientStorageDataFromValue(BStorage::Value&& value)
	{
		ClientStorageData result{};
		BStorage::Value::ObjectMap* object = value.asObject();
		if (object != nullptr)
		{
			if (auto it = object->find(ConfirmedField); it != object->end())
			{
				ReadConfirmedServerBindingsFromValue(std::move(it->second), result.confirmedServerBindings);
			}
			if (auto it = object->find(SentFilesField); it != object->end())
			{
				ReadSentFilesFromValue(std::move(it->second), result.sentFiles);
			}
			if (auto it = object->find(PartiallySentFilesField); it != object->end())
			{
				ReadPartiallySentFilesFromValue(std::move(it->second), result.partiallySentFiles);
			}
		}
		return result;
	}
} // namespace ClientStorageInternal

#ifdef WITH_TESTS
ClientStorage ClientStorage::testCreateEmpty() noexcept
{
	return ClientStorage("test_client_storage.bin", BStorage::Value::makeObject({}));
}
#endif // WITH_TESTS

ClientStorage ClientStorage::load(const std::filesystem::path& storageDirectory) noexcept
{
	std::filesystem::path storagePath = storageDirectory / ClientStorageInternal::ClientStorageFileName;
	std::optional<std::tuple<BStorage::Value, uint16_t>> loaded = BStorage::loadStorage(storagePath);

	if (loaded.has_value())
	{
		if (std::get<1>(*loaded) != ClientStorageInternal::ClientStorageVersion)
		{
			// here we need to have an update path
			return ClientStorage(std::move(storagePath), BStorage::Value::makeObject({}));
		}

		return ClientStorage(std::move(storagePath), std::get<0>(std::move(*loaded)));
	}
	else
	{
		return ClientStorage(std::move(storagePath), BStorage::Value::makeObject({}));
	}
}

bool ClientStorage::save() const noexcept
{
	using namespace ClientStorageInternal;

	std::lock_guard g(mMutex);
	return BStorage::saveStorage(mStoragePath, WriteClientStorageDataToValue(mStorageData), ClientStorageVersion);
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

ClientStorage::ClientStorage(std::filesystem::path&& storagePath, BStorage::Value&& value) noexcept
	: mStoragePath(std::move(storagePath))
	, mStorageData(ClientStorageInternal::ReadClientStorageDataFromValue(std::move(value)))
{
}
