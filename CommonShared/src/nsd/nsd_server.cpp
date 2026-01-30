// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/nsd/nsd_server.h"

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
#include <cstring>
#include <format>
#include <ranges>
#include <string>

namespace NsdServer
{
	[[noreturn]] static void unreachable()
	{
#if defined(_MSC_VER) && !defined(__clang__) // MSVC
		__assume(false);
#else // GCC, Clang
		__builtin_unreachable();
#endif
	}

	static int addressTypeToFamily(const AddressType type)
	{
		switch (type)
		{
		case AddressType::IpV4:
			return AF_INET;
		case AddressType::IpV6:
			return AF_INET6;
		}
		unreachable();
	}

	static const char* addressTypeToStr(const AddressType type)
	{
		switch (type)
		{
		case AddressType::IpV4:
			return "IPv4";
		case AddressType::IpV6:
			return "IPv6";
		}
		unreachable();
	}

	static uint16_t checksum16(const std::span<std::byte>& data)
	{
		// this is a very trivial checksum, eventually we want crc16 here
		uint16_t checksum = 0;
		for (uint16_t i = 0; i < data.size(); ++i)
		{
			checksum ^= static_cast<uint16_t>(data[i]) << ((i & 0x1) * 8);
		}
		return checksum;
	}

	static void writeBigEndian(std::vector<std::byte>& outVec, const uint16_t value)
	{
		if constexpr (std::endian::native == std::endian::little)
		{
			// ReSharper disable once CppDFAUnreachableCode
			outVec.push_back(static_cast<std::byte>((value & 0xff00) >> 8));
			outVec.push_back(static_cast<std::byte>(value & 0xff));
		}
		else
		{
			// ReSharper disable once CppDFAUnreachableCode
			outVec.push_back(static_cast<std::byte>(value & 0xff));
			outVec.push_back(static_cast<std::byte>((value & 0xff00) >> 8));
		}
	}

	static ListenResult bindSocket(const int socketToBind, const char* interfaceAddressStr, const AddressType addressType, const uint16_t port)
	{
		const int addressFamily = addressTypeToFamily(addressType);

		if (addressType == AddressType::IpV4)
		{
			sockaddr_in address;
			if (interfaceAddressStr != nullptr)
			{
				const int errCode = inet_pton(addressFamily, interfaceAddressStr, &address.sin_addr);
				switch (errCode)
				{
				case -1:
					return std::format("Not supported address type provided: '{}', error code {} '{}'.", interfaceAddressStr, errno, strerror(errno));
				case 0:
					return std::format("Address '{}' is not supported for address family {}.", interfaceAddressStr, addressTypeToStr(addressType));
				default:
					break;
				}
			}
			else
			{
				address.sin_addr.s_addr = INADDR_ANY;
			}

			address.sin_family = addressFamily;
			address.sin_port = htons(port);

			const int errCode = bind(socketToBind, std::bit_cast<const sockaddr*>(&address), sizeof(address));
			if (errCode == -1)
			{
				return std::format("Cannot bind the socket, error code {} '{}'.", errno, strerror(errno));
			}
		}
		else
		{
			sockaddr_in6 address;
			if (interfaceAddressStr != nullptr)
			{
				const int errCode = inet_pton(addressFamily, interfaceAddressStr, &address.sin6_addr);
				switch (errCode)
				{
				case -1:
					return std::format("Not supported address type provided: '{}'.", interfaceAddressStr);
				case 0:
					return std::format("Address '{}' is not supported for address family {}.", interfaceAddressStr, addressTypeToStr(addressType));
				default:
					break;
				}
			}
			else
			{
				address.sin6_addr = IN6ADDR_ANY_INIT;
			}

			address.sin6_family = addressFamily;
			address.sin6_port = htons(port);

			const int errCode = bind(socketToBind, std::bit_cast<const sockaddr*>(&address), sizeof(address));
			if (errCode == -1)
			{
				return std::format("Cannot bind the socket, error code {} '{}'.", errno, strerror(errno));
			}
		}
		return std::nullopt;
	}

	ListenResult listen(
		const char* interfaceAddressStr,
		const AddressType addressType,
		const uint16_t port,
		const char* serviceId,
		const uint16_t advertizedPort,
		const std::vector<std::byte>& extraData
	)
	{
		if (serviceId == nullptr)
		{
			return "serviceId can't be nullptr";
		}

		const int nsdSocket = socket(addressTypeToFamily(addressType), SOCK_DGRAM, 0);
		if (nsdSocket == -1)
		{
			return std::format("Error when creating socket, error code {} '{}'.", errno, strerror(errno));
		}

		constexpr int flagTrue = 1;
		int errCode = setsockopt(nsdSocket, SOL_SOCKET, SO_REUSEADDR, &flagTrue, sizeof(flagTrue));
		if (errCode == -1)
		{
			return std::format("Cannot set SO_REUSEADDR to the UDP socket, error code {} '{}'.", errno, strerror(errno));
		}

		errCode = setsockopt(nsdSocket, SOL_SOCKET, SO_REUSEPORT, &flagTrue, sizeof(flagTrue));
		if (errCode == -1)
		{
			return std::format("Cannot set SO_REUSEPORT to the UDP socket, error code {} '{}'.", errno, strerror(errno));
		}

		const ListenResult result = bindSocket(nsdSocket, interfaceAddressStr, addressType, port);
		if (result.has_value())
		{
			return result;
		}

		const std::string expectedPacket = std::format("aloha:{}\n", serviceId);
		if (expectedPacket.size() > 1024)
		{
			return std::format("Service ID is too long, maximum size is 1017 bytes, the ID length was {} bytes instead.", expectedPacket.size());
		}

		const size_t responseSize = 1 + 2 + 2 + extraData.size() + 2;
		if (responseSize > std::numeric_limits<uint16_t>::max())
		{
			return std::format("Response size is too big, maximum size is 65535 bytes, the data size was {} bytes instead.", responseSize);
		}

		std::vector<std::byte> response;
		response.reserve(responseSize);
		response.push_back(static_cast<std::byte>(0x01)); // protocol version
		writeBigEndian(response, static_cast<uint16_t>(extraData.size())); // size of extra data
		writeBigEndian(response, advertizedPort); // port
		std::ranges::copy(extraData, std::back_inserter(response)); // extra data
		writeBigEndian(response, checksum16(std::span(response.begin() + 3, response.end()))); // checksum

		if (response.size() != responseSize)
		{
			return std::format("The actual size of response is {} bytes, expected {} bytes.", response.size(), responseSize);
		}

		constexpr size_t BUFFER_SIZE = 1024;
		char buf[BUFFER_SIZE];
		ssize_t messageLength;
		sockaddr clientAddr;
		socklen_t clientAddrLen = sizeof(clientAddr);
		while ((messageLength = recvfrom(nsdSocket, buf, BUFFER_SIZE, 0, &clientAddr, &clientAddrLen)) != -1)
		{
			if (messageLength != expectedPacket.size())
			{
				continue;
			}

			if (std::memcmp(buf, expectedPacket.data(), expectedPacket.size()) != 0)
			{
				continue;
			}

			{
				const ssize_t sentSize = sendto(nsdSocket, response.data(), responseSize, 0, &clientAddr, clientAddrLen);
				if (sentSize == -1)
				{
					return std::format("Failed to send response to UDP socket, error code {} '{}'.", errno, strerror(errno));
				}
			}
		}

		return std::format("Failed to receive from UDP socket, error code {} '{}'.", errno, strerror(errno));
	}
} // namespace NsdServer
