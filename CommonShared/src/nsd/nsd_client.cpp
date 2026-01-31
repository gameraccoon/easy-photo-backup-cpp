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

namespace NsdClient
{
	static uint16_t readBigEndianUint16(const char byte1, const char byte2)
	{
		if constexpr (std::endian::native == std::endian::little)
		{
			// ReSharper disable once CppDFAUnreachableCode
			return (static_cast<uint16_t>(byte1) << 8) | static_cast<uint16_t>(byte2);
		}
		else
		{
			// ReSharper disable once CppDFAUnreachableCode
			return static_cast<uint16_t>(byte1) | (static_cast<uint16_t>(byte2) << 8);
		}
	}

	static std::string buildNsdQuery(const char* serviceIdentifier)
	{
		return std::format("aloha:{}\n", serviceIdentifier);
	}

	std::optional<std::string> broadcastNdsUdpRequest(const int socket, const NsdTypes::AddressType addressType, const std::string_view query, const uint16_t port)
	{
		ssize_t sentSize;
		if (addressType == NsdTypes::AddressType::IpV4)
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

	struct NetworkAddress
	{
		sockaddr addr;
		socklen_t addrLen;

		bool operator==(const NetworkAddress& other) const noexcept
		{
			return addrLen == other.addrLen && std::memcmp(&addr, &other.addr, addrLen) == 0;
		}
	};

	bool processUdpRequestAnswer(const int socket, char* const inOutBuffer, const size_t bufferSize, NetworkAddress& outNetAddress, uint16_t& outPort, std::vector<std::byte>& outExtraData)
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
		if (inOutBuffer[0] != 0x01)
		{
			return false;
		}

		const size_t extraDataLen = readBigEndianUint16(inOutBuffer[1], inOutBuffer[2]);

		if (messageLength != 1 + 2 + 2 + extraDataLen + 2)
		{
			return false;
		}

		outPort = readBigEndianUint16(inOutBuffer[3], inOutBuffer[4]);
		const uint16_t receivedChecksum = readBigEndianUint16(
			inOutBuffer[5 + extraDataLen],
			inOutBuffer[6 + extraDataLen]
		);

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

	ListenResult startServiceDiscoveryThread(
		const char* serviceIdentifier,
		const uint16_t broadcastPort,
		const NsdTypes::AddressType addressType,
		const float broadcastPeriodSec,
		const std::function<void(DiscoveryResult&&)>& resultFunction,
		const std::atomic_bool& stopSignalReceiver
	)
	{
		using namespace NsdInternalUtils;

		if (serviceIdentifier == nullptr)
		{
			return "service identifier can't be nullptr";
		}

		std::variant<int, std::string> createSocketResult = createSocket(SocketType::Broadcast, addressType);
		if (std::holds_alternative<std::string>(createSocketResult))
		{
			return std::get<std::string>(createSocketResult);
		}

		const AutoclosingSocket socket = AutoclosingSocket(std::get<int>(std::move(createSocketResult)));

		const std::optional<std::string> bindSocketResult = bindSocket(socket, nullptr, addressType, 0);
		if (bindSocketResult.has_value())
		{
			return bindSocketResult;
		}

		// 200 milliseconds means that 5 times per second we will check if the stop signal has been received
		timeval socketTimeout;
		socketTimeout.tv_sec = 0;
		socketTimeout.tv_usec = 200000;
		const int errCode = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &socketTimeout, sizeof(socketTimeout));
		if (errCode == -1)
		{
			return std::format("Cannot set SO_RCVTIMEO to the UDP socket, error code {} '{}'.", errno, strerror(errno));
		}

		// the std::vector solution is optimized for up to 8 servers, but up to 100 should be fine
		// the assumption is that we won't have more than 1-2 servers at a time anyway

		// we count generations based on our send timer
		// we don't care about when we sent the broadcast that got the server to us
		constexpr int GENERATIONS_TO_MISS_TO_REMOVE = 2;
		std::array<std::vector<NetworkAddress>, GENERATIONS_TO_MISS_TO_REMOVE> discoveryGenerations;

		std::vector<NetworkAddress> onlineServers;
		std::vector<NetworkAddress> serversToRemove;

		const std::string query = buildNsdQuery(serviceIdentifier);

		constexpr size_t BUFFER_SIZE = 1024;
		char buffer[BUFFER_SIZE];
		NetworkAddress netAddress;
		std::vector<std::byte> extraData;
		std::string nameBuffer;

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
				{
					const std::optional<std::string> result = broadcastNdsUdpRequest(socket, addressType, query, broadcastPort);
					if (result.has_value())
					{
						return result;
					}
				}
				lastBroadcastTime = std::chrono::steady_clock::now();

				// remove servers that are no longer online
				serversToRemove.clear();
				for (const NetworkAddress& server : onlineServers)
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

				for (const NetworkAddress& server : serversToRemove)
				{
					uint16_t port;
					if (!parseAddress(&server.addr, server.addrLen, nameBuffer, port).has_value())
					{
						resultFunction(DiscoveryResult{
							.address = ServiceAddress{
								.ip = "test",
								.port = 90,
							},
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
					uint16_t port1;
					if (!parseAddress(&netAddress.addr, netAddress.addrLen, nameBuffer, port1).has_value())
					{
						resultFunction(DiscoveryResult{
							.address = ServiceAddress{
								.ip = nameBuffer,
								.port = port,
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
