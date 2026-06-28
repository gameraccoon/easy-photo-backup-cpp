// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <thread>

#include "common_shared/network/utils.h"
#include "common_shared/nsd/nsd_client.h"

#include "client_shared/test_full_file_backup.h"
int main()
{
	Network::initSocketLib();

	TestFullFileBackup test{ "." };
	test.startDiscovery();
	std::vector<TestServerInfo> discoveryResults;
	int tries = 0;
	do {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		discoveryResults = test.getDiscoveryResults();
		++tries;
	} while (discoveryResults.empty() && tries < 1000);
	test.stopDiscovery();

	if (!discoveryResults.empty())
	{
		test.pairAndApproveServer(discoveryResults.front());

		test.sendFiles(discoveryResults.front(), "./client_files_to_send", "./client_files_to_send");
	}

	Network::shutdownSocketLib();

	return 0;
}
