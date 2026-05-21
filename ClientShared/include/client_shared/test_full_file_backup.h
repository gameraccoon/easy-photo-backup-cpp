// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <atomic>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include "common_shared/network/utils.h"

#include "client_shared/client_storage.h"

// This is a test implementation for quick testing of file transfer
// it should be removed as soon as a complete interactive implementation is ready
// for android and desktop

class TestFullFileBackup
{
public:
	TestFullFileBackup();

	void startDiscovery();
	std::vector<Network::NetworkAddress> getDiscoveryResults();
	void stopDiscovery();

	std::optional<std::string> requestServerName(Network::NetworkAddress address);

	// this is the bad and dangerous part, should be removed altogether before the app can be used for real
	void pairAndApproveServer(Network::NetworkAddress address, const std::string& serverName);

	void sendFiles(Network::NetworkAddress address, const std::string& serverName, const std::string& folderPath);

private:
	std::mutex mDataMutex;
	std::thread mDiscoveryThread;
	std::vector<Network::NetworkAddress> mDiscoveredServers;
	std::atomic_bool mNsdStopFlag{};
	ClientStorage mClientStorage;
};
