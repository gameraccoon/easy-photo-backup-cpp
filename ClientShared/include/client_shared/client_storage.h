// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <filesystem>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include "common_shared/bstorage/value.h"
#include "common_shared/cryptography/types/dh_types.h"
#include "common_shared/cryptography/types/hash_types.h"

struct ClientStorageData
{
	struct ServerBinding
	{
		Cryptography::HashResult connectionId;
		Cryptography::PublicKey remoteStaticKey;
		Cryptography::Keypair staticKeys;
	};

	std::unordered_multimap<std::string, ServerBinding> confirmedServerBindings;
	std::unordered_set<std::string> sentFiles;
};

class ClientStorage
{
public:
#ifdef WITH_TESTS
	static ClientStorage testCreateEmpty() noexcept;
#endif // WITH_TESTS

	[[nodiscard]] static ClientStorage load(const std::filesystem::path& storageDirectory) noexcept;
	[[nodiscard]] bool save() const noexcept;

	void read(const std::function<void(const ClientStorageData&)>& readFn) const noexcept;
	void mutate(const std::function<void(ClientStorageData&)>& mutateFn) noexcept;

private:
	explicit ClientStorage(std::filesystem::path&& storagePath, BStorage::Value&& value) noexcept;

private:
	std::filesystem::path mStoragePath;
	ClientStorageData mStorageData;
	mutable std::mutex mMutex;
};
