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

struct ServerStorageData
{
	struct ClientBinding
	{
		Cryptography::PublicKey remoteStaticKey;
		Cryptography::Keypair staticKeys;
	};

	struct PendingClientBinding
	{
		Cryptography::PublicKey remoteStaticKey;
		Cryptography::Keypair staticKeys;
		Cryptography::HashResult handshakeHash;
		std::chrono::time_point<std::chrono::system_clock> expiryTime;
	};

	std::unordered_multimap<std::string, ClientBinding> confirmedClientBindings;
	std::unordered_multimap<std::string, PendingClientBinding> pendingConfirmationBindings;
};

class ServerStorage
{
public:
	static ServerStorage load() noexcept;
	[[nodiscard]] bool save() const noexcept;

	void read(const std::function<void(const ServerStorageData&)>& readFn) const noexcept;
	void mutate(const std::function<void(ServerStorageData&)>& mutateFn) noexcept;

private:
	explicit ServerStorage(BStorage::Value&& value) noexcept;

private:
	ServerStorageData mStorageData;
	mutable std::mutex mMutex;
};
