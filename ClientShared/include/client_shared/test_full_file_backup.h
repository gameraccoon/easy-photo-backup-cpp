// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <atomic>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>
#include <filesystem>

#include "common_shared/network/utils.h"

#include "client_shared/client_storage.h"

// This is a test implementation for quick testing of file transfer
// it should be removed as soon as a complete interactive implementation is ready
// for android and desktop

class TestFullFileBackup
{
public:
	TestFullFileBackup(const std::filesystem::path& storageDirectory);

	void startDiscovery();
	std::vector<Network::NetworkAddress> getDiscoveryResults();
	void stopDiscovery();

	static std::optional<std::string> requestServerName(const Network::NetworkAddress& address);

	// this is the bad and dangerous part, should be removed altogether before the app can be used for real
	std::optional<std::string> pairAndApproveServer(const Network::NetworkAddress& address, const std::string& serverName);

	std::optional<std::string> sendFiles(const Network::NetworkAddress& address, const std::string& serverName, const std::string& folderPath, const std::string& commonRoot);

	std::optional<std::string> removeServer(const std::string& serverName);

	bool isServerPaired(const std::string& serverName) const;

private:
	std::mutex mDataMutex;
	std::thread mDiscoveryThread;
	std::vector<Network::NetworkAddress> mDiscoveredServers;
	std::atomic_bool mNsdStopFlag{};
	ClientStorage mClientStorage;
};
