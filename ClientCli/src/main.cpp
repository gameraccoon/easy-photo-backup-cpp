// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <condition_variable>
#include <format>
#include <thread>

#include "common_shared/debug/assert.h"
#include "common_shared/debug/log.h"
#include "common_shared/nsd/nsd_client.h"
#include "common_shared/template_utils.h"

#include "client_shared/client_storage.h"
#include "client_shared/pairing_interactive_request.h"
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

						Debug::Log::printDebug(std::format("NSD: Server added v={}, id='{}', ip='{}', port='{}'", version, idString, event.address.ip, event.address.port));
						{
							std::unique_lock lock(serversMutex);
							servers.push_back(event.address);
						}
						serversChanged.notify_all();
					}
					else
					{
						Debug::Log::printDebug("NSD: Server removed");
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
			Debug::Log::printDebug(std::format("NSD client error: '{}'", *result));
			exit(0);
		}
		else
		{
			Debug::Log::printDebug("NSD client stopped without errors");
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

	ClientStorage storage = ClientStorage::load();

	RequestAnswers::RequestAnswer nameAnswer = Requests::sendAndProcessRequest(foundServer.ip.data(), foundServer.addressType, foundServer.port, Requests::GetServerName{});

	std::string serverName;
	std::visit(
		VisitLambda{
			[&serverName](RequestAnswers::GetServerName&& getServerName) {
				serverName = getServerName.serverName;
				Debug::Log::printDebug(getServerName.serverName);
			},
			[](RequestAnswers::UnsupportedProtocolVersion&& unsupportedProtocolVersion) {
				Debug::Log::printDebug(std::format("The server rejected our protocol version, expected version {}", unsupportedProtocolVersion.firstSupportedProtocolVersion));
				exit(0);
			},
			[](RequestAnswers::Error&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
				exit(0);
			},
			[](RequestAnswers::LogicalError&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
				exit(0);
			},
			[](auto&&) {
				Debug::Log::printDebug("logical error, unexpected answer");
				exit(0);
			},
		},
		std::move(nameAnswer)
	);

	RequestAnswers::RequestAnswer answer = Requests::prepareConnectionAndProcess(
		foundServer.ip.data(),
		foundServer.addressType,
		foundServer.port,
		[](Network::RawSocket socket) -> RequestAnswers::RequestAnswer {
			return Requests::sendAndProcessPairingInteractiveRequest(socket);
		}
	);

	std::visit(
		VisitLambda{
			[&storage, &serverName](RequestAnswers::Pair&& pair) {
				storage.mutate([&serverName, &pair](ClientStorageData& storage) {
					storage.pendingConfirmationBindings.emplace(
						serverName,
						ClientStorageData::PendingServerBinding{
							.remoteStaticKey = std::move(pair.remoteStaticKey),
							.staticKeys = std::move(pair.staticKeys),
							.handshakeHash = std::move(pair.handshakeHash),
							.expiryTime = std::chrono::system_clock::now(),
						}
					);
				});

				if (storage.save() == false)
				{
					reportDebugError("Could not save client data");
				}
				Debug::Log::printDebug(std::format("Successfully paired to server '{}'", serverName));
			},
			[](RequestAnswers::UnsupportedProtocolVersion&& unsupportedProtocolVersion) {
				Debug::Log::printDebug(std::format("The server rejected our protocol version, expected version {}", unsupportedProtocolVersion.firstSupportedProtocolVersion));
				exit(0);
			},
			[](RequestAnswers::Error&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
				exit(0);
			},
			[](RequestAnswers::LogicalError&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
				exit(0);
			},
			[](auto&&) {
				Debug::Log::printDebug("logical error, unexpected answer");
				exit(0);
			},
		},
		std::move(answer)
	);

	// wait for the thread to finish
	nsdThread.join();

	return 0;
}
