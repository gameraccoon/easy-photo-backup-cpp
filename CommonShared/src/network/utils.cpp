// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/network/utils.h"

#include <algorithm>
#include <bit>
#include <climits>
#include <cstring>
#include <format>

#include "common_shared/debug/assert.h"
#include "common_shared/network/raw_sockets.h"

namespace Network
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

	static std::optional<int> parseInt(const char* str)
	{
		char* end;
		errno = 0;
		const long l = std::strtol(str, &end, 10);
		if ((errno == ERANGE && l == LONG_MAX) || l > INT_MAX) [[unlikely]]
		{
			return std::nullopt;
		}
		if ((errno == ERANGE && l == LONG_MIN) || l < INT_MIN) [[unlikely]]
		{
			return std::nullopt;
		}
		if (*str == '\0' || *end != '\0') [[unlikely]]
		{
			return std::nullopt;
		}
		return static_cast<int>(l);
	}

	std::variant<NetworkAddress, std::string> parseAddress(const void* const addr, const size_t addrLen)
	{
		char name[INET6_ADDRSTRLEN];

		char portStr[10];
		if (getnameinfo(static_cast<const sockaddr*>(addr), addrLen, name, sizeof(name), portStr, sizeof(portStr), NI_NUMERICHOST | NI_NUMERICSERV) == -1) [[unlikely]]
		{
			reportDebugError("Can't convert socket address to string, error code {} '{}'", errno, strerror(errno));
			return std::format("Can't convert socket address to string, error code {} '{}'", errno, strerror(errno));
		}

		NetworkAddress resultAddress;

		// processing short IPv6 addresses (end with %)
		const auto it = std::find(name, name + INET6_ADDRSTRLEN, '%');
		if (it != name + INET6_ADDRSTRLEN)
		{
			resultAddress.ip = std::string(name, it);
		}
		else
		{
			resultAddress.ip = name;
		}

		resultAddress.port = parseInt(portStr).value_or(0);

		resultAddress.addressType = static_cast<const sockaddr*>(addr)->sa_family == AF_INET6 ? AddressType::IpV6 : AddressType::IpV4;

		return resultAddress;
	}

	std::variant<int, std::string> createSocket(const SocketType type, const AddressType addressType)
	{
		const int addressFamily = addressTypeToFamily(addressType);

		int socketType = SOCK_DGRAM;
		switch (type)
		{
		case SocketType::Tcp:
			socketType = SOCK_STREAM;
			break;
		case SocketType::Udp:
			socketType = SOCK_DGRAM;
			break;
		}

		const int newSocket = socket(addressFamily, socketType, 0);
		if (newSocket == -1) [[unlikely]]
		{
			reportDebugError("Error when creating socket, error code {} '{}'.", errno, strerror(errno));
			return std::format("Error when creating socket, error code {} '{}'.", errno, strerror(errno));
		}

		return newSocket;
	}

	std::optional<std::string> setSocketOption(const int socket, const int optionName)
	{
		constexpr int flagTrue = 1;
		if (const int errCode = setsockopt(socket, SOL_SOCKET, optionName, &flagTrue, sizeof(flagTrue)); errCode == -1) [[unlikely]]
		{
			reportDebugError("Cannot set option {} to the socket, error code {} '{}'.", optionName, errno, strerror(errno));
			return std::format("Cannot set option {} to the socket, error code {} '{}'.", optionName, errno, strerror(errno));
		}
		return std::nullopt;
	}

	std::optional<std::string> setSocketTimeout(int socket, const int optionName, int seconds, int microseconds)
	{
		timeval socketTimeout;
		socketTimeout.tv_sec = seconds;
		socketTimeout.tv_usec = microseconds;
		if (const int errCode = setsockopt(socket, SOL_SOCKET, optionName, &socketTimeout, sizeof(socketTimeout)); errCode == -1) [[unlikely]]
		{
			reportDebugError("Cannot set option {} to the socket, error code {} '{}'.", optionName, errno, strerror(errno));
			return std::format("Cannot set option {} to the socket, error code {} '{}'.", optionName, errno, strerror(errno));
		}
		return std::nullopt;
	}

	std::variant<uint16_t, std::string> getSocketPort(int socket)
	{
		sockaddr address;
		socklen_t addrlen = sizeof(address);
		if (getsockname(socket, static_cast<sockaddr*>(&address), &addrlen) != 0) [[unlikely]]
		{
			reportDebugError("Could not read port from socket, error code {} '{}'.", errno, strerror(errno));
			return std::format("Could not read port from socket, error code {} '{}'.", errno, strerror(errno));
		}

		if (address.sa_family == AF_INET)
		{
			if (sizeof(sockaddr_in) != addrlen) [[unlikely]]
			{
				reportDebugError("Unexpected IPv4 address size {}", addrlen);
				return std::format("Unexpected IPv4 address size {}", addrlen);
			}

			return ntohs(std::bit_cast<sockaddr_in*>(&address)->sin_port);
		}
		else if (address.sa_family == AF_INET6)
		{
			if (sizeof(sockaddr_in6) != addrlen) [[unlikely]]
			{
				reportDebugError("Unexpected IPv6 address size {}", addrlen);
				return std::format("Unexpected IPv6 address size {}", addrlen);
			}

			return ntohs(std::bit_cast<sockaddr_in6*>(&address)->sin6_port);
		}

		reportDebugError("Unknown address family {}", address.sa_family);
		return std::format("Unknown address family {}", address.sa_family);
	}

	std::variant<NetworkAddress, std::string> getSocketAddress(int socket)
	{
		sockaddr address;
		socklen_t addrlen = sizeof(address);
		if (getsockname(socket, static_cast<sockaddr*>(&address), &addrlen) != 0) [[unlikely]]
		{
			reportDebugError("Could not read port from socket, error code {} '{}'.", errno, strerror(errno));
			return std::format("Could not read port from socket, error code {} '{}'.", errno, strerror(errno));
		}

		return parseAddress(&address, addrlen);
	}

	std::optional<std::string> bindSocket(const int socket, const char* const interfaceAddressStr, const AddressType addressType, const uint16_t port)
	{
		const int addressFamily = addressTypeToFamily(addressType);

		auto innerBind = [](auto& address, int socket) -> std::optional<std::string> {
			const int errCode = bind(socket, std::bit_cast<const sockaddr*>(&address), sizeof(address));
			if (errCode == -1) [[unlikely]]
			{
				reportDebugError("Cannot bind socket, error code {} '{}'.", errno, strerror(errno));
				return std::format("Cannot bind socket, error code {} '{}'.", errno, strerror(errno));
			}
			return std::nullopt;
		};

		if (addressType == AddressType::IpV4)
		{
			sockaddr_in address;
			if (interfaceAddressStr != nullptr)
			{
				const int errCode = inet_pton(addressFamily, interfaceAddressStr, &address.sin_addr);
				switch (errCode)
				{
				[[unlikely]] case -1:
					reportDebugError("Not supported address type provided: '{}', error code {} '{}'.", interfaceAddressStr, errno, strerror(errno));
					return std::format("Not supported address type provided: '{}', error code {} '{}'.", interfaceAddressStr, errno, strerror(errno));
				[[unlikely]] case 0:
					reportDebugError("Address '{}' is not supported for address family {}.", interfaceAddressStr, addressTypeToStr(addressType));
					return std::format("Address '{}' is not supported for address family {}.", interfaceAddressStr, addressTypeToStr(addressType));
				[[likely]] default:
					break;
				}
			}
			else
			{
				address.sin_addr.s_addr = INADDR_ANY;
			}

			address.sin_family = addressFamily;
			address.sin_port = htons(port);

			return innerBind(address, socket);
		}
		else
		{
			sockaddr_in6 address;
			if (interfaceAddressStr != nullptr)
			{
				const int errCode = inet_pton(addressFamily, interfaceAddressStr, &address.sin6_addr);
				switch (errCode)
				{
				[[unlikely]] case -1:
					reportDebugError("Not supported address type provided: '{}'.", interfaceAddressStr);
					return std::format("Not supported address type provided: '{}'.", interfaceAddressStr);
				[[unlikely]] case 0:
					reportDebugError("Address '{}' is not supported for address family {}.", interfaceAddressStr, addressTypeToStr(addressType));
					return std::format("Address '{}' is not supported for address family {}.", interfaceAddressStr, addressTypeToStr(addressType));
				[[likely]] default:
					break;
				}
			}
			else
			{
				address.sin6_addr = IN6ADDR_ANY_INIT;
			}

			address.sin6_family = addressFamily;
			address.sin6_port = htons(port);

			return innerBind(address, socket);
		}

		return std::nullopt;
	}

	std::optional<std::string> connectToServer(const int socket, const char* const address, const AddressType addressType, const uint16_t port)
	{
		auto innerConnect = [](auto& addr, int socket, const char* address, uint16_t port) -> std::optional<std::string> {
			if (int result = connect(socket, (sockaddr*)&addr, sizeof(addr)); result == -1) [[unlikely]]
			{
				return std::format("Cannot connect to the address {}:{}, error code {} '{}'.", address, port, errno, strerror(errno));
			}

			return std::nullopt;
		};

		if (addressType == AddressType::IpV4)
		{
			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			const int errCode = inet_pton(AF_INET, address, &addr.sin_addr);
			switch (errCode)
			{
			[[unlikely]] case -1:
				reportDebugError("Not supported address type provided: '{}'.", address);
				return std::format("Not supported address type provided: '{}'.", address);
			[[unlikely]] case 0:
				reportDebugError("Address '{}' is not supported for address family {}.", address, addressTypeToStr(addressType));
				return std::format("Address '{}' is not supported for address family {}.", address, addressTypeToStr(addressType));
			[[likely]] default:
				break;
			}

			return innerConnect(addr, socket, address, port);
		}
		else
		{
			sockaddr_in6 addr;
			addr.sin6_family = AF_INET6;
			addr.sin6_port = htons(port);
			const int errCode = inet_pton(AF_INET, address, &addr.sin6_addr);
			switch (errCode)
			{
			[[unlikely]] case -1:
				reportDebugError("Not supported address type provided: '{}'.", address);
				return std::format("Not supported address type provided: '{}'.", address);
			[[unlikely]] case 0:
				reportDebugError("Address '{}' is not supported for address family {}.", address, addressTypeToStr(addressType));
				return std::format("Address '{}' is not supported for address family {}.", address, addressTypeToStr(addressType));
			[[likely]] default:
				break;
			}

			return innerConnect(addr, socket, address, port);
		}
	}

	std::optional<std::string> send(int socket, std::span<std::byte> data)
	{
		const ssize_t sentSize = ::send(socket, data.data(), data.size(), 0);
		if (sentSize == -1) [[unlikely]]
		{
			return std::format("Failed to send data to socket, error code {} '{}'.", errno, strerror(errno));
		}

		if (sentSize == 0) [[unlikely]]
		{
			reportDebugError("Sent size was zero, this is unexpected");
			return std::string("Sent size was zero, this is unexpected");
		}

		assertFatalRelease(sentSize <= static_cast<ssize_t>(data.size()), "send wrote more bytes than the size of the buffer. This should never happen and may signal about a vulnerability. We have to crash so signal about the severity of this.");

		if (sentSize != static_cast<ssize_t>(data.size())) [[unlikely]]
		{
			reportDebugError("Sent size was different from the message size, this is not expected. Expected: {}, sent: {}", data.size(), sentSize);
			return std::format("Sent size was different from the message size, this is not expected. Expected: {}, sent: {}", data.size(), sentSize);
		}

		return std::nullopt;
	}

	std::optional<std::string> recv(int socket, std::span<std::byte> outData, size_t& receivedBytes)
	{
		const ssize_t messageSize = ::recv(socket, outData.data(), outData.size(), 0);
		if (messageSize == -1) [[unlikely]]
		{
			return std::format("Failed to read response from TCP socket, error code {} '{}'.", errno, strerror(errno));
		}

		if (messageSize < 0) [[unlikely]]
		{
			reportDebugError("Received message size was less than -1, this is not expected: {}", messageSize);
			return std::format("Received message size was less than -1, this is not expected: {}", messageSize);
		}

		if (messageSize == 0) [[unlikely]]
		{
			return std::string("Received message size was zero, possibly reached the timeout");
		}

		assertFatalRelease(messageSize <= static_cast<ssize_t>(outData.size()), "recv wrote more bytes than the size of the buffer. This should never happen and may result in buffer overflow vulnerability. We have to crash.");

		if (messageSize > static_cast<ssize_t>(outData.size())) [[unlikely]]
		{
			// we should have crashed already in the assert above, but just in case treat it as an error
			return std::string{};
		}

		receivedBytes = static_cast<size_t>(messageSize);
		return std::nullopt;
	}

	void closeSocket(const int socket)
	{
		shutdown(socket, SHUT_RDWR);
		close(socket);
	}
} // namespace Network
