// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <thread>

#include "common_shared/debug/log.h"
#include "common_shared/network/utils.h"
#include "common_shared/nsd/nsd_client.h"
#include "common_shared/template_utils.h"

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
		std::variant<std::string, PendingServerBinding> pairintExchangeResult = test.exchangePairInformationWithServer(discoveryResults.front());

		std::visit(
			VisitLambda{
				[](std::string&& error) {
					Debug::Log::printDebug("Error when exchanging pairing information: {}", std::move(error));
				},
				[&serverAddress = discoveryResults.front(), &test](PendingServerBinding&& pendingBinding) {
					if (auto error = test.approveServer(serverAddress, std::move(pendingBinding)); error.has_value())
					{
						Debug::Log::printDebug("Error when pairing: {}", std::move(*error));
						return;
					}

					if (auto error = test.sendFiles(serverAddress, "./client_files_to_send", "./client_files_to_send"); error.has_value())
					{
						Debug::Log::printDebug("Error when exchanging files: {}", std::move(*error));
						return;
					}
				},
			},
			std::move(pairintExchangeResult)
		);
	}

	Network::shutdownSocketLib();

	return 0;
}
