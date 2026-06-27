// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <thread>

#include "common_shared/network/utils.h"

#include "client_shared/test_full_file_backup.h"

int main()
{
	Network::initSocketLib();

	TestFullFileBackup test{ "." };
	test.startDiscovery();
	std::vector<Network::NetworkAddress> discoveryResults;
	int tries = 0;
	do {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		discoveryResults = test.getDiscoveryResults();
		++tries;
	} while (discoveryResults.empty() && tries < 1000);
	test.stopDiscovery();

	const std::optional<std::string> serverName = test.requestServerName(discoveryResults.front());

	if (!serverName.has_value())
	{
		return 1;
	}

	test.pairAndApproveServer(discoveryResults.front(), *serverName);

	test.sendFiles(discoveryResults.front(), *serverName, "./client_files_to_send", "./client_files_to_send");

	Network::shutdownSocketLib();

	return 0;
}
