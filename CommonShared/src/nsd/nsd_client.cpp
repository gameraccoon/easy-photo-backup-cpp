// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/nsd/nsd_client.h"

#include "common_shared/nsd/utils_internal.h"

#if _WIN32
#include <winsock32.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <bit>
#include <chrono>
#include <cstring>
#include <format>

#include "common_shared/serialization/number_serialization.h"

namespace NsdClient
{
	static std::string buildNsdQuery(const char* serviceIdentifier)
	{
		return std::format("aloha:{}\n", serviceIdentifier);
	}

	static std::optional<std::string> broadcastNdsUdpRequest(const int socket, const Network::AddressType addressType, const std::string_view query, const uint16_t port)
	{
		ssize_t sentSize;
		if (addressType == Network::AddressType::IpV4)
		{
			sockaddr_in address;
			address.sin_addr.s_addr = INADDR_BROADCAST;
			address.sin_family = AF_INET;
			address.sin_port = htons(port);
			sentSize = sendto(socket, query.data(), query.size(), 0, std::bit_cast<const sockaddr*>(&address), sizeof(address));
		}
		else
		{
			return std::format("IPV6 broadcast (multicast) is somewhat complicated, it isn't implemented for now. Add when needed");
		}

		if (sentSize == -1)
		{
			return std::format("Failed to send NSD broadcast to UDP socket, error code {} '{}'.", errno, strerror(errno));
		}

		return std::nullopt;
	}

	struct NetworkAddressKey
	{
		sockaddr addr;
		socklen_t addrLen = sizeof(sockaddr);

		bool operator==(const NetworkAddressKey& other) const noexcept
		{
			return addrLen == other.addrLen && std::memcmp(&addr, &other.addr, addrLen) == 0;
		}
	};

	static bool processUdpRequestAnswer(const int socket, std::byte* const inOutBuffer, const size_t bufferSize, NetworkAddressKey& outNetAddress, uint16_t& outPort, std::vector<std::byte>& outExtraData)
	{
		// for the simplicity sake, we use UDP to communicate back as well
		// this can miss packets sometimes, but it's fine for our use case
		const int messageLength = recvfrom(socket, inOutBuffer, bufferSize, 0, &outNetAddress.addr, &outNetAddress.addrLen);
		if (messageLength == -1)
		{
			// either failure or timeout, we don't destinguish them right now
			return false;
		}

		if (messageLength < 1 + 2 + 2 + 0 + 2)
		{
			return false;
		}

		// the only supported protocol version for now is 1
		if (inOutBuffer[0] != std::byte(0x01))
		{
			return false;
		}

		const size_t extraDataLen = Serialization::readUint16(inOutBuffer[1], inOutBuffer[2]);

		if (messageLength != 1 + 2 + 2 + extraDataLen + 2)
		{
			return false;
		}

		outPort = Serialization::readUint16(inOutBuffer[3], inOutBuffer[4]);
		const uint16_t receivedChecksum = Serialization::readUint16(inOutBuffer[5 + extraDataLen], inOutBuffer[6 + extraDataLen]);

		const uint16_t actualChecksum = NsdInternalUtils::checksum16v1(std::span(
			std::bit_cast<std::byte*>(inOutBuffer + 3),
			std::bit_cast<std::byte*>(inOutBuffer + (3 + 2 + extraDataLen))
		));

		if (receivedChecksum != actualChecksum)
		{
			return false;
		}

		outExtraData.clear();
		std::copy(
			std::bit_cast<std::byte*>(inOutBuffer + 5),
			std::bit_cast<std::byte*>(inOutBuffer + 5 + extraDataLen),
			std::back_inserter(outExtraData)
		);

		return true;
	}

	ListenResult processServiceDiscoveryThread(
		const char* serviceIdentifier,
		const uint16_t broadcastPort,
		const Network::AddressType addressType,
		const float broadcastPeriodSec,
		const std::function<void(DiscoveryResult&&)>& resultFunction,
		const std::atomic_bool& stopSignalReceiver
	)
	{
		if (serviceIdentifier == nullptr)
		{
			return "service identifier can't be nullptr";
		}

		std::variant<int, std::string> createSocketResult = Network::createSocket(Network::SocketType::Udp, addressType);
		if (std::holds_alternative<std::string>(createSocketResult))
		{
			return std::get<std::string>(createSocketResult);
		}

		const Network::AutoclosingSocket socket = Network::AutoclosingSocket(std::get<int>(std::move(createSocketResult)));

		if (auto result = Network::setSocketOption(socket, SO_BROADCAST); result.has_value())
		{
			return result;
		}

		// 200 milliseconds means that 5 times per second we will check if the stop signal has been received
		if (const auto result = Network::setSocketTimeout(socket, SO_RCVTIMEO, 0, 200000); result.has_value())
		{
			return result;
		}

		if (const auto result = Network::bindSocket(socket, nullptr, addressType, 0); result.has_value())
		{
			return result;
		}

		// the std::vector solution is optimized for up to 8 servers, but up to 100 should be fine
		// the assumption is that we won't have more than 1-2 servers at a time anyway

		// we count generations based on our send timer
		// we don't care about when we sent the broadcast that got the server to us
		constexpr int GENERATIONS_TO_MISS_TO_REMOVE = 2;
		std::array<std::vector<NetworkAddressKey>, GENERATIONS_TO_MISS_TO_REMOVE> discoveryGenerations;

		std::vector<NetworkAddressKey> onlineServers;
		std::vector<NetworkAddressKey> serversToRemove;

		const std::string query = buildNsdQuery(serviceIdentifier);

		constexpr size_t BUFFER_SIZE = 1024;
		std::byte buffer[BUFFER_SIZE];
		NetworkAddressKey netAddress{};
		std::vector<std::byte> extraData;

		// set the time in the past, enough to trigger the broadcast immediately
		const std::chrono::duration broadcastPeriod = std::chrono::round<std::chrono::nanoseconds>(std::chrono::duration<float>(broadcastPeriodSec));
		std::chrono::time_point lastBroadcastTime = std::chrono::steady_clock::now() - (broadcastPeriod * 2);

		while (true)
		{
			if (stopSignalReceiver.load(std::memory_order::relaxed))
			{
				return std::nullopt;
			}

			if (std::chrono::steady_clock::now() > lastBroadcastTime + broadcastPeriod)
			{
				if (const auto result = broadcastNdsUdpRequest(socket, addressType, query, broadcastPort); result.has_value())
				{
					return result;
				}
				lastBroadcastTime = std::chrono::steady_clock::now();

				// remove servers that are no longer online
				serversToRemove.clear();
				for (const NetworkAddressKey& server : onlineServers)
				{
					bool found = false;
					for (size_t i = 0; i < GENERATIONS_TO_MISS_TO_REMOVE; ++i)
					{
						if (std::ranges::find(discoveryGenerations[i], server) != discoveryGenerations[i].end())
						{
							found = true;
							break;
						}
					}
					if (!found)
					{
						serversToRemove.push_back(server);
					}
				}

				if (!serversToRemove.empty())
				{
					for (size_t i = onlineServers.size(); i > 0; --i)
					{
						if (std::ranges::find(serversToRemove, onlineServers[i - 1]) != serversToRemove.end())
						{
							onlineServers.erase(onlineServers.begin() + (i - 1));
						}
					}
				}

				for (const NetworkAddressKey& server : serversToRemove)
				{
					auto result = Network::parseAddress(&server.addr, server.addrLen);
					if (std::holds_alternative<Network::NetworkAddress>(result))
					{
						resultFunction(DiscoveryResult{
							.address = std::move(std::get<Network::NetworkAddress>(result)),
							.extraData = std::vector<std::byte>{},
							.state = DiscoveryState::Removed,
						});
					}
				}

				std::rotate(discoveryGenerations.data(), discoveryGenerations.data() + (GENERATIONS_TO_MISS_TO_REMOVE - 1), discoveryGenerations.data() + GENERATIONS_TO_MISS_TO_REMOVE);
				discoveryGenerations[0].clear();
			}

			uint16_t port;
			if (processUdpRequestAnswer(socket, buffer, BUFFER_SIZE, netAddress, port, extraData))
			{
				if (std::ranges::find(discoveryGenerations[0], netAddress) == discoveryGenerations[0].end())
				{
					discoveryGenerations[0].push_back(netAddress);
				}

				if (std::ranges::find(onlineServers, netAddress) == onlineServers.end())
				{
					onlineServers.push_back(netAddress);
					auto result = Network::parseAddress(&netAddress.addr, netAddress.addrLen);
					if (std::holds_alternative<Network::NetworkAddress>(result))
					{
						resultFunction(DiscoveryResult{
							.address = Network::NetworkAddress{
								.ip = std::get<Network::NetworkAddress>(result).ip,
								.port = port,
								.addressType = std::get<Network::NetworkAddress>(result).addressType,
							},
							.extraData = extraData,
							.state = DiscoveryState::Added,
						});
					}
				}
			}
		}
	}
} // namespace NsdClient
