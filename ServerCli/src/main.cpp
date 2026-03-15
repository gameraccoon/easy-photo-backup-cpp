// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <atomic>
#include <format>
#include <thread>

#include "common_shared/debug/log.h"
#include "common_shared/nsd/nsd_server.h"

#include "server_shared/tcp_server.h"

int main()
{
	auto openSocketResult = NsdServer::openNsdSocket(Network::AddressType::IpV4);

	if (std::holds_alternative<std::string>(openSocketResult))
	{
		Debug::Log::printDebug(std::get<std::string>(openSocketResult));
		return 0;
	}

	const Network::RawSocket socket = std::get<Network::RawSocket>(openSocketResult);
	std::atomic_bool nsdCloseSocketFlag{};

	auto stopNsdServer = [socket, &nsdCloseSocketFlag] {
		if (nsdCloseSocketFlag.load(std::memory_order::acquire) == false)
		{
			nsdCloseSocketFlag.store(true, std::memory_order::acq_rel);
			Network::closeSocket(socket);
		}
	};

	std::promise<uint16_t> portPromise{};
	std::future<uint16_t> portFuture = portPromise.get_future();

	auto serverThread = std::thread([&portPromise] {
		TcpServer::runServer("0.0.0.0", Network::AddressType::IpV4, portPromise);
	});

	if (auto status = portFuture.wait_for(std::chrono::seconds(3)); status != std::future_status::ready)
	{
		Debug::Log::printDebug("Didn't receive the server port in time");
		return 0;
	}

	const uint16_t serverPort = portFuture.get();

	std::thread nsdThread([socket, &nsdCloseSocketFlag, serverPort] {
		const std::vector<std::byte> extraData{ {
			static_cast<std::byte>(1), // protocol id
			static_cast<std::byte>(0), // the rest is the server ID
			static_cast<std::byte>(1),
			static_cast<std::byte>(2),
			static_cast<std::byte>(3),
			static_cast<std::byte>(4),
			static_cast<std::byte>(5),
			static_cast<std::byte>(6),
			static_cast<std::byte>(7),
			static_cast<std::byte>(8),
			static_cast<std::byte>(9),
			static_cast<std::byte>(10),
			static_cast<std::byte>(11),
			static_cast<std::byte>(12),
			static_cast<std::byte>(13),
			static_cast<std::byte>(14),
			static_cast<std::byte>(15),
		} };

		NsdServer::ListenResult result = NsdServer::listen(socket, "0.0.0.0", Network::AddressType::IpV4, 5354, "_easy-photo-backup._tcp", serverPort, extraData);

		if (std::holds_alternative<NsdServer::SetupError>(result))
		{
			Debug::Log::printDebug(std::format("NSD server setup error: '{}'", std::get<NsdServer::SetupError>(result).error));
		}
		else
		{
			// if we didn't stop intentionally
			if (nsdCloseSocketFlag.load(std::memory_order::acquire) == false)
			{
				Debug::Log::printDebug(std::format("NSD server error: '{}'", std::get<NsdServer::SocketError>(result).error));
				nsdCloseSocketFlag.store(true, std::memory_order::release);
				Network::closeSocket(socket);
			}
			else
			{
				Debug::Log::printDebug("NSD server stopped without errors");
			}
		}
	});

	serverThread.join();

	stopNsdServer();
	// wait for the thread to finish
	nsdThread.join();

	return 0;
}
