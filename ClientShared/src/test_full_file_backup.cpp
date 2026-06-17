// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/test_full_file_backup.h"

#include <format>

#include "common_shared/debug/assert.h"
#include "common_shared/debug/log.h"
#include "common_shared/nsd/nsd_client.h"
#include "common_shared/template_utils.h"

#include "client_shared/client_storage.h"
#include "client_shared/pairing_interactive_request.h"
#include "client_shared/requests.h"
#include "client_shared/send_files_interactive_request.h"

struct PendingServerBinding
{
	Cryptography::Keypair staticKeys;
	Cryptography::PublicKey remoteStaticKey;
	Cryptography::HashResult handshakeHash;
};

TestFullFileBackup::TestFullFileBackup()
	: mClientStorage(ClientStorage::load())
{
}

void TestFullFileBackup::startDiscovery()
{
	mDiscoveryThread = std::thread([&servers = mDiscoveredServers, &mutex = mDataMutex, &nsdStopFlag = mNsdStopFlag] {
		std::optional<std::string> result = NsdClient::processServiceDiscoveryThread(
				"_easy-photo-backup._tcp",
				5354,
				Network::AddressType::IpV4,
				1,
				[&servers, &mutex](auto&& event) {
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
							std::unique_lock lock(mutex);
							servers.push_back(event.address);
						}
					}
					else
					{
						Debug::Log::printDebug("NSD: Server removed");
						{
							std::unique_lock lock(mutex);
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
					}
				},
				nsdStopFlag
			);

		if (result.has_value())
		{
			Debug::Log::printDebug(std::format("NSD client error: '{}'", *result));
		}
		else
		{
			Debug::Log::printDebug("NSD client stopped without errors");
		}
	});
}

std::vector<Network::NetworkAddress> TestFullFileBackup::getDiscoveryResults()
{
	std::unique_lock lock(mDataMutex);
	return mDiscoveredServers;
}

void TestFullFileBackup::stopDiscovery()
{
	mNsdStopFlag.store(true, std::memory_order::release);
	mDiscoveredServers.clear();
	mDiscoveryThread.join();
	mNsdStopFlag.store(false, std::memory_order::relaxed);
}

std::optional<std::string> TestFullFileBackup::requestServerName(const Network::NetworkAddress& address)
{
	RequestAnswers::RequestAnswer nameAnswer = Requests::sendAndProcessRequest(address.ip.data(), address.addressType, address.port, Requests::GetServerName{});

	std::optional<std::string> serverName;
	std::visit(
		VisitLambda{
			[&serverName](RequestAnswers::GetServerName&& getServerName) {
				serverName = getServerName.serverName;
				Debug::Log::printDebug(getServerName.serverName);
			},
			[](RequestAnswers::UnsupportedProtocolVersion&& unsupportedProtocolVersion) {
				Debug::Log::printDebug(std::format("The server rejected our protocol version, expected version {}", unsupportedProtocolVersion.firstSupportedProtocolVersion));
			},
			[](RequestAnswers::Error&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
			},
			[](RequestAnswers::LogicalError&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
			},
			[](auto&&) {
				Debug::Log::printDebug("logical error, unexpected answer");
			},
		},
		std::move(nameAnswer)
	);

	return serverName;
}

void TestFullFileBackup::pairAndApproveServer(const Network::NetworkAddress& address, const std::string& serverName)
{
	bool isPaired = false;
	mClientStorage.read([&isPaired, &serverName](const ClientStorageData& storageData) {
		if (auto it = storageData.confirmedServerBindings.find(serverName); it != storageData.confirmedServerBindings.end())
		{
			isPaired = true;
		}
	});

	if (isPaired)
	{
		return;
	}

	RequestAnswers::RequestAnswer pairAnswer = Requests::prepareConnectionAndProcess(
		address.ip.data(),
		address.addressType,
		address.port,
		[](Network::RawSocket socket) -> RequestAnswers::RequestAnswer {
			return Requests::sendAndProcessPairingInteractiveRequest(socket);
		}
	);

	std::optional<PendingServerBinding> pendingServerBinding;

	std::visit(
		VisitLambda{
			[&pendingServerBinding, &serverName](RequestAnswers::Pair&& pair) {
				pendingServerBinding = PendingServerBinding{
					.staticKeys = std::move(pair.staticKeys),
					.remoteStaticKey = std::move(pair.remoteStaticKey),
					.handshakeHash = std::move(pair.handshakeHash),
				};
				Debug::Log::printDebug(std::format("Received pairing information from '{}'", serverName));
			},
			[](RequestAnswers::UnsupportedProtocolVersion&& unsupportedProtocolVersion) {
				Debug::Log::printDebug(std::format("The server rejected our protocol version, expected version {}", unsupportedProtocolVersion.firstSupportedProtocolVersion));
			},
			[](RequestAnswers::Error&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
			},
			[](RequestAnswers::LogicalError&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
			},
			[](auto&&) {
				Debug::Log::printDebug("logical error, unexpected answer");
			},
		},
		std::move(pairAnswer)
	);

	// approve automatically for now
	{
		if (!pendingServerBinding.has_value())
		{
			Debug::Log::printDebug("pendingServerBinding is not set, this is incorrect");
		}

		mClientStorage.mutate([&serverName, &pendingServerBinding](ClientStorageData& storage) {
			storage.confirmedServerBindings.emplace(
				serverName,
				ClientStorageData::ServerBinding{
					.remoteStaticKey = std::move(pendingServerBinding->remoteStaticKey),
					.staticKeys = std::move(pendingServerBinding->staticKeys),
				}
			);
		});

		pendingServerBinding = std::nullopt;

		if (mClientStorage.save() == false)
		{
			reportDebugError("Could not save client data");
		}

		Debug::Log::printDebug("The server got automatically approved for testing purposes");
	}
}

void TestFullFileBackup::sendFiles(const Network::NetworkAddress& address, const std::string& serverName, const std::string& folderPath)
{
	RequestAnswers::RequestAnswer SendFilesAnswer = Requests::prepareConnectionAndProcess(
		address.ip.data(),
		address.addressType,
		address.port,
		[&storage = mClientStorage, &serverName, &folderPath](Network::RawSocket socket) -> RequestAnswers::RequestAnswer {
			return Requests::sendAndProcessSendFilesInteractiveRequest(socket, storage, serverName, folderPath);
		}
	);

	std::visit(
		VisitLambda{
			[](RequestAnswers::SendFiles&&) {
				Debug::Log::printDebug(std::format("Successfully sent files"));
			},
			[](RequestAnswers::UnsupportedProtocolVersion&& unsupportedProtocolVersion) {
				Debug::Log::printDebug(std::format("The server rejected our protocol version, expected version {}", unsupportedProtocolVersion.firstSupportedProtocolVersion));
			},
			[](RequestAnswers::Error&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
			},
			[](RequestAnswers::LogicalError&& answerReadError) {
				Debug::Log::printDebug(answerReadError.errorMessage);
			},
			[](auto&&) {
				Debug::Log::printDebug("logical error, unexpected answer");
			},
		},
		std::move(SendFilesAnswer)
	);
}
