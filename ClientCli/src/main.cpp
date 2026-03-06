// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <condition_variable>
#include <format>
#include <thread>

#include "common_shared/debug/log.h"
#include "common_shared/nsd/nsd_client.h"
#include "common_shared/template_utils.h"

#include "client_shared/requests.h"

int main()
{
	std::atomic_bool nsdStopFlag{};

	std::vector<Network::NetworkAddress> servers;
	std::mutex serversMutex;
	std::condition_variable serversChanged;

	std::thread nsdThread([&servers, &serversMutex, &serversChanged, &nsdStopFlag] {
		std::optional<std::string>
			result = NsdClient::processServiceDiscoveryThread(
				"_easy-photo-backup._tcp",
				5354,
				Network::AddressType::IpV4,
				1,
				[&servers, &serversMutex, &serversChanged](auto&& event) {
					if (event.state == NsdClient::DiscoveryState::Added)
					{
						int version = -1;
						if (!event.extraData.empty())
						{
							version = static_cast<int>(event.extraData[0]);
						}

						std::string idString;
						idString.reserve(event.extraData.size());
						for (std::byte b : event.extraData)
						{
							idString.push_back(static_cast<int>(b) + '0');
						}

						debug::log::printDebug(std::format("Server added v={}, id='{}', ip='{}', port='{}'", version, idString, event.address.ip, event.address.port));
						{
							std::unique_lock lock(serversMutex);
							servers.push_back(event.address);
						}
						serversChanged.notify_all();
					}
					else
					{
						debug::log::printDebug("Server removed");
						{
							std::unique_lock lock(serversMutex);
							auto it = std::find_if(
								servers.begin(),
								servers.end(),
								[&event](const Network::NetworkAddress& item) {
									return item.ip == event.address.ip;
								}
							);

							if (it != servers.end())
							{
								servers.erase(it);
							}
						}
						serversChanged.notify_all();
					}
				},
				nsdStopFlag
			);

		if (result.has_value())
		{
			debug::log::printDebug(std::format("NSD client error: '{}'", *result));
		}
		else
		{
			debug::log::printDebug("NSD client stopped without errors");
		}
	});

	Network::NetworkAddress foundServer;
	while (true)
	{
		std::unique_lock lock(serversMutex);
		// wait until we have non-empty servers
		serversChanged.wait(lock, [&] { return !servers.empty(); });

		foundServer = servers[0];

		nsdStopFlag.store(true, std::memory_order::release);

		break;
	}

	RequestAnswers::RequestAnswer answer = Requests::sendAndProcessRequest(foundServer.ip.data(), foundServer.addressType, foundServer.port, Requests::RequestGetServerName{});

	std::visit(
		VisitLambda{
			[](RequestAnswers::AnswerGetServerName&& answerGetServerName) {
				debug::log::printDebug(answerGetServerName.name);
			},
			[](RequestAnswers::ExpectedNoAnswer) {
				debug::log::printDebug("logical error");
			},
			[](RequestAnswers::Error&& answerReadError) {
				debug::log::printDebug(answerReadError.errorMessage);
			},
			[](RequestAnswers::LogicalError&& answerReadError) {
				debug::log::printDebug(answerReadError.errorMessage);
			},
		},
		std::move(answer)
	);

	// wait for the thread to finish
	nsdThread.join();

	return 0;
}
