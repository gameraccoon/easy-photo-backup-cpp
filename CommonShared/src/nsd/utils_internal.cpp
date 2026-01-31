// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

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

#include <algorithm>
#include <climits>
#include <cstring>
#include <format>

namespace NsdInternalUtils
{
	[[noreturn]] static void unreachable()
	{
#if defined(_MSC_VER) && !defined(__clang__) // MSVC
		__assume(false);
#else // GCC, Clang
		__builtin_unreachable();
#endif
	}

	static int addressTypeToFamily(const NsdTypes::AddressType type)
	{
		switch (type)
		{
		case NsdTypes::AddressType::IpV4:
			return AF_INET;
		case NsdTypes::AddressType::IpV6:
			return AF_INET6;
		}
		unreachable();
	}

	static const char* addressTypeToStr(const NsdTypes::AddressType type)
	{
		switch (type)
		{
		case NsdTypes::AddressType::IpV4:
			return "IPv4";
		case NsdTypes::AddressType::IpV6:
			return "IPv6";
		}
		unreachable();
	}

	static std::optional<int> parseInt(const char* str)
	{
		char* end;
		errno = 0;
		const long l = std::strtol(str, &end, 10);
		if ((errno == ERANGE && l == LONG_MAX) || l > INT_MAX)
		{
			return std::nullopt;
		}
		if ((errno == ERANGE && l == LONG_MIN) || l < INT_MIN)
		{
			return std::nullopt;
		}
		if (*str == '\0' || *end != '\0')
		{
			return std::nullopt;
		}
		return static_cast<int>(l);
	}

	std::optional<std::string> parseAddress(const void* const addr, const size_t addrLen, std::string& outIp, uint16_t& outPort)
	{
		std::string addressString;
		char name[INET6_ADDRSTRLEN];

		char portStr[10];
		if (getnameinfo(static_cast<const sockaddr*>(addr), addrLen, name, sizeof(name), portStr, sizeof(portStr), NI_NUMERICHOST | NI_NUMERICSERV) == -1)
		{
			return std::format("Can't convert socket address to string, error code {} '{}'", errno, strerror(errno));
		}

		// processing short IPv6 addresses (end with %)
		const auto it = std::find(name, name + INET6_ADDRSTRLEN, '%');
		if (it != name + INET6_ADDRSTRLEN)
		{
			outIp = std::string(name, it);
		}
		else
		{
			outIp = name;
		}

		outPort = parseInt(portStr).value_or(0);

		return std::nullopt;
	}

	std::variant<int, std::string> createSocket(const SocketType type, const NsdTypes::AddressType addressType)
	{
		const int addressFamily = addressTypeToFamily(addressType);

		const int newSocket = socket(addressFamily, SOCK_DGRAM, 0);
		if (newSocket == -1)
		{
			return std::format("Error when creating socket, error code {} '{}'.", errno, strerror(errno));
		}

		constexpr int flagTrue = 1;

		switch (type)
		{
		case SocketType::NsdListen: {
			int errCode = setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &flagTrue, sizeof(flagTrue));
			if (errCode == -1)
			{
				return std::format("Cannot set SO_REUSEADDR to the UDP socket, error code {} '{}'.", errno, strerror(errno));
			}

			errCode = setsockopt(newSocket, SOL_SOCKET, SO_REUSEPORT, &flagTrue, sizeof(flagTrue));
			if (errCode == -1)
			{
				return std::format("Cannot set SO_REUSEPORT to the UDP socket, error code {} '{}'.", errno, strerror(errno));
			}
			break;
		}
		case SocketType::Broadcast: {
			const int errCode = setsockopt(newSocket, SOL_SOCKET, SO_BROADCAST, &flagTrue, sizeof(flagTrue));
			if (errCode == -1)
			{
				return std::format("Cannot set SO_BROADCAST to the UDP socket, error code {} '{}'.", errno, strerror(errno));
			}
			break;
		}
		}

		return newSocket;
	}

	std::optional<std::string> bindSocket(const int socket, const char* const interfaceAddressStr, const NsdTypes::AddressType addressType, const uint16_t port)
	{
		const int addressFamily = addressTypeToFamily(addressType);

		if (addressType == NsdTypes::AddressType::IpV4)
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

			const int errCode = bind(socket, std::bit_cast<const sockaddr*>(&address), sizeof(address));
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

			const int errCode = bind(socket, std::bit_cast<const sockaddr*>(&address), sizeof(address));
			if (errCode == -1)
			{
				return std::format("Cannot bind the socket, error code {} '{}'.", errno, strerror(errno));
			}
		}

		return std::nullopt;
	}

	void closeSocket(const int socket)
	{
		shutdown(socket, SHUT_RDWR);
		close(socket);
	}

	uint16_t checksum16v1(const std::span<std::byte>& data)
	{
		// this is a very trivial checksum, eventually we want crc16 here
		uint16_t checksum = 0;
		for (uint16_t i = 0; i < data.size(); ++i)
		{
			checksum ^= static_cast<uint16_t>(data[i]) << ((i & 0x1) * 8);
		}
		return checksum;
	}
} // namespace NsdInternalUtils
