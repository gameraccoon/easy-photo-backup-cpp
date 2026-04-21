// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <unordered_map>

#include "common_shared/bstorage/value.h"
#include "common_shared/cryptography/types/dh_types.h"
#include "common_shared/cryptography/types/hash_types.h"

struct ClientStorageData
{
	struct ServerBinding
	{
		Cryptography::PublicKey remoteStaticKey;
		Cryptography::Keypair staticKeys;
	};

	std::unordered_multimap<std::string, ServerBinding> confirmedServerBindings;
};

class ClientStorage
{
public:
	static ClientStorage load() noexcept;
	[[nodiscard]] bool save() const noexcept;

	void read(const std::function<void(const ClientStorageData&)>& readFn) const noexcept;
	void mutate(const std::function<void(ClientStorageData&)>& mutateFn) noexcept;

private:
	explicit ClientStorage(BStorage::Value&& value) noexcept;

private:
	ClientStorageData mStorageData;
	mutable std::mutex mMutex;
};
