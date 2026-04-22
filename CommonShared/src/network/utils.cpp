// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/network/utils.h"

#include <algorithm>
#include <climits>
#include <cstring>
#include <format>

#include "common_shared/cryptography/noise/cipher_utils.h"
#include "common_shared/cryptography/utils/crypto_wipe.h"
#include "common_shared/debug/assert.h"
#include "common_shared/network/raw_sockets.h"

namespace Network
{
	constexpr bool debugPrintBuffers = false;

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
		if (getnameinfo(static_cast<const sockaddr*>(addr), static_cast<socklen_t>(addrLen), name, sizeof(name), portStr, sizeof(portStr), NI_NUMERICHOST | NI_NUMERICSERV) == -1) [[unlikely]]
		{
			reportDebugError("Can't convert socket address to string, error code {}", errno);
			return std::format("Can't convert socket address to string, error code {}", errno);
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

		resultAddress.port = static_cast<uint16_t>(parseInt(portStr).value_or(0));

		resultAddress.addressType = static_cast<const sockaddr*>(addr)->sa_family == AF_INET6 ? AddressType::IpV6 : AddressType::IpV4;

		return resultAddress;
	}

	std::variant<RawSocket, std::string> createSocket(const SocketType type, const AddressType addressType)
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

		const RawSocket newSocket = socket(addressFamily, socketType, 0);
		if (newSocket == -1) [[unlikely]]
		{
			reportDebugError("Error when creating socket, error code {}.", errno);
			return std::format("Error when creating socket, error code {}.", errno);
		}

		return newSocket;
	}

	std::optional<std::string> setSocketOption(const RawSocket socket, const int optionName)
	{
		constexpr int flagTrue = 1;
		if (const int errCode = setsockopt(socket, SOL_SOCKET, optionName, reinterpret_cast<const char*>(&flagTrue), sizeof(flagTrue)); errCode == -1) [[unlikely]]
		{
			reportDebugError("Cannot set option {} to the socket, error code {}.", optionName, errno);
			return std::format("Cannot set option {} to the socket, error code {}.", optionName, errno);
		}
		return std::nullopt;
	}

	std::optional<std::string> setSocketTimeout(RawSocket socket, const int optionName, int seconds, int microseconds)
	{
		timeval socketTimeout{};
		socketTimeout.tv_sec = seconds;
		socketTimeout.tv_usec = microseconds;
		if (const int errCode = setsockopt(socket, SOL_SOCKET, optionName, reinterpret_cast<const char*>(&socketTimeout), sizeof(socketTimeout)); errCode == -1) [[unlikely]]
		{
			reportDebugError("Cannot set option {} to the socket, error code {}.", optionName, errno);
			return std::format("Cannot set option {} to the socket, error code {}.", optionName, errno);
		}
		return std::nullopt;
	}

	std::variant<uint16_t, std::string> getSocketPort(RawSocket socket)
	{
		sockaddr address;
		socklen_t addrlen = sizeof(address);
		if (getsockname(socket, static_cast<sockaddr*>(&address), &addrlen) != 0) [[unlikely]]
		{
			reportDebugError("Could not read port from socket, error code {}.", errno);
			return std::format("Could not read port from socket, error code {}.", errno);
		}

		if (address.sa_family == AF_INET)
		{
			if (sizeof(sockaddr_in) != addrlen) [[unlikely]]
			{
				reportDebugError("Unexpected IPv4 address size {}", addrlen);
				return std::format("Unexpected IPv4 address size {}", addrlen);
			}

			return ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port);
		}
		else if (address.sa_family == AF_INET6)
		{
			if (sizeof(sockaddr_in6) != addrlen) [[unlikely]]
			{
				reportDebugError("Unexpected IPv6 address size {}", addrlen);
				return std::format("Unexpected IPv6 address size {}", addrlen);
			}

			return ntohs(reinterpret_cast<sockaddr_in6*>(&address)->sin6_port);
		}

		reportDebugError("Unknown address family {}", address.sa_family);
		return std::format("Unknown address family {}", address.sa_family);
	}

	std::variant<NetworkAddress, std::string> getSocketAddress(const RawSocket socket)
	{
		sockaddr address;
		socklen_t addrlen = sizeof(address);
		if (getsockname(socket, static_cast<sockaddr*>(&address), &addrlen) != 0) [[unlikely]]
		{
			reportDebugError("Could not read port from socket, error code {}.", errno);
			return std::format("Could not read port from socket, error code {}.", errno);
		}

		return parseAddress(&address, addrlen);
	}

	std::optional<std::string> bindSocket(const RawSocket socket, const char* const interfaceAddressStr, const AddressType addressType, const uint16_t port)
	{
		const int addressFamily = addressTypeToFamily(addressType);

		auto innerBind = [](auto& address, RawSocket socket) -> std::optional<std::string> {
			const int errCode = bind(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
			if (errCode == -1) [[unlikely]]
			{
				reportDebugError("Cannot bind socket, error code {}.", errno);
				return std::format("Cannot bind socket, error code {}.", errno);
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
					reportDebugError("Not supported address type provided: '{}', error code {}.", interfaceAddressStr, errno);
					return std::format("Not supported address type provided: '{}', error code {}.", interfaceAddressStr, errno);
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

#if _WIN32
			address.sin_family = static_cast<ADDRESS_FAMILY>(addressFamily);
#else
			address.sin_family = addressFamily;
#endif
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

#if _WIN32
			address.sin6_family = static_cast<ADDRESS_FAMILY>(addressFamily);
#else
			address.sin6_family = addressFamily;
#endif
			address.sin6_port = htons(port);

			return innerBind(address, socket);
		}
	}

	std::optional<std::string> connectToServer(const RawSocket socket, const char* const address, const AddressType addressType, const uint16_t port)
	{
		auto innerConnect = [](auto& addr, RawSocket socket, const char* address, uint16_t port) -> std::optional<std::string> {
			if (int result = connect(socket, (sockaddr*)&addr, sizeof(addr)); result == -1) [[unlikely]]
			{
				return std::format("Cannot connect to the address {}:{}, error code {}.", address, port, errno);
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

	std::optional<std::string> send(const RawSocket socket, std::span<const std::byte> data)
	{
		const auto sentSize = ::send(socket, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), MSG_NOSIGNAL);
		if (sentSize == -1) [[unlikely]]
		{
			return std::format("Failed to send data to socket, error code {}.", errno);
		}

		if (sentSize == 0) [[unlikely]]
		{
			reportDebugError("Sent size was zero, this is unexpected");
			return std::string("Sent size was zero, this is unexpected");
		}

		assertFatalRelease(sentSize <= static_cast<int>(data.size()), "send wrote more bytes than the size of the buffer. This should never happen and may signal about a vulnerability. We have to crash so signal about the severity of this.");

		if (sentSize != static_cast<int>(data.size())) [[unlikely]]
		{
			reportDebugError("Sent size was different from the message size, this is not expected. Expected: {}, sent: {}", data.size(), sentSize);
			return std::format("Sent size was different from the message size, this is not expected. Expected: {}, sent: {}", data.size(), sentSize);
		}

		if constexpr (debugPrintBuffers)
		{
			printf("send: 0x");
			for (std::byte b : data)
			{
				printf("%02X", static_cast<uint8_t>(b));
			}
			printf("\n");
			fflush(stdout);
		}

		return std::nullopt;
	}

	std::optional<std::string> recv(const RawSocket socket, std::span<std::byte> outData, size_t& receivedBytes)
	{
		const auto messageSize = ::recv(socket, reinterpret_cast<char*>(outData.data()), static_cast<int>(outData.size()), 0);
		if (messageSize == -1) [[unlikely]]
		{
			return std::format("Failed to read response from TCP socket, error code {}.", errno);
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

		assertFatalRelease(messageSize <= static_cast<int>(outData.size()), "recv wrote more bytes than the size of the buffer. This should never happen and may result in buffer overflow vulnerability. We have to crash.");

		if (messageSize > static_cast<int>(outData.size())) [[unlikely]]
		{
			// we should have crashed already in the assert above, but just in case treat it as an error
			return std::string{};
		}

		if constexpr (debugPrintBuffers)
		{
			printf("recv: 0x");
			for (std::byte b : std::span(outData.begin(), messageSize))
			{
				printf("%02X", static_cast<uint8_t>(b));
			}
			printf("\n");
			fflush(stdout);
		}

		receivedBytes = static_cast<size_t>(messageSize);
		return std::nullopt;
	}

	std::optional<std::string> sendEncrypted(RawSocket socket, std::span<std::byte> buffer, size_t bytesToSend, Noise::CipherStateSending& cipherState)
	{
		if (buffer.size() < bytesToSend + Cryptography::CipherAuthDataSize)
		{
			reportDebugError("The buffer is too small to fit the cyphertext to send, {} {}", buffer.size(), bytesToSend + Cryptography::CipherAuthDataSize);
			return std::format("The buffer is too small to fit the cyphertext to send, {} {}", buffer.size(), bytesToSend + Cryptography::CipherAuthDataSize);
		}

		if (bytesToSend == 0)
		{
			reportDebugError("Tried to send zero bytes, this signals about a logical error");
			return std::format("Tried to send zero bytes, this signals about a logical error");
		}

		if constexpr (debugPrintBuffers)
		{
			printf("send (before encryption): 0x");
			for (std::byte b : std::span(buffer.data(), bytesToSend))
			{
				printf("%02X", static_cast<uint8_t>(b));
			}
			printf("\n");
			fflush(stdout);
		}

		const Cryptography::EncryptResult encryptResult = Noise::Utils::encryptWithAd(cipherState, {}, std::span<std::byte>(buffer.data(), bytesToSend), std::span<std::byte>(buffer.data(), bytesToSend + Cryptography::CipherAuthDataSize));

		switch (encryptResult)
		{
		case Cryptography::EncryptResult::Success:
			return send(socket, std::span<std::byte>(buffer.data(), bytesToSend + Cryptography::CipherAuthDataSize));
		case Cryptography::EncryptResult::PlaintextBiggerThanMaxMessageSize:
			return "Plaintext is too big to be encrypted";
		case Cryptography::EncryptResult::CiphertextBufferTooSmall:
			return "Cipthertext buffer is too small to fit the result";
		case Cryptography::EncryptResult::CiphertextBufferTooBig:
			return "Ciphertext buffer is bigger than expected";
		case Cryptography::EncryptResult::IncorrectEncryptionKey:
			return "Encryption key is not valid (empty)";
		case Cryptography::EncryptResult::PartiallyOverlappingBuffers:
			return "Plaintext and ciphertext buffers are not allowed to partially oveerlap";
		case Cryptography::EncryptResult::NoEncryptionKey:
			return "No encryption key was provided";
		case Cryptography::EncryptResult::NonceExhausted:
			return "Nonce has been exhausted, can't send any more data in this stream";
		}

		return "Unreachable code reached";
	}

	std::optional<std::string> recvEncrypted(RawSocket socket, std::span<std::byte> buffer, size_t& receivedBytes, Noise::CipherStateReceiving& cipherState)
	{
		if (buffer.size() <= Cryptography::CipherAuthDataSize)
		{
			return "Buffer is too small to fit any non-zero message";
		}

		if (auto recvResult = recv(socket, buffer, receivedBytes); recvResult.has_value())
		{
			return recvResult;
		}

		if (receivedBytes <= Cryptography::CipherAuthDataSize)
		{
			return "Received data is too small to be decrypted";
		}

		const Cryptography::DecryptResult decryptResult = Noise::Utils::decryptWithAd(cipherState, {}, std::span<std::byte>(buffer.data(), receivedBytes), std::span<std::byte>(buffer.data(), receivedBytes - Cryptography::CipherAuthDataSize));

		switch (decryptResult)
		{
		case Cryptography::DecryptResult::Success:
			if constexpr (debugPrintBuffers)
			{
				printf("recv (after decryption): 0x");
				for (std::byte b : std::span<std::byte>(buffer.data(), receivedBytes - Cryptography::CipherAuthDataSize))
				{
					printf("%02X", static_cast<uint8_t>(b));
				}
				printf("\n");
				fflush(stdout);
			}

			receivedBytes -= Cryptography::CipherAuthDataSize;
			Cryptography::cryptoWipeRawData(std::span(buffer.data() + receivedBytes, Cryptography::CipherAuthDataSize));
			return std::nullopt;
		case Cryptography::DecryptResult::AuthDataMismatch:
			return "Auth data mismatch, the byte stream is corrupted or tempered with";
		case Cryptography::DecryptResult::CiphertextSmallerThanMac:
			return "Ciphertext is smaller than authentification data";
		case Cryptography::DecryptResult::CiphertextBiggerThanMessageLimit:
			return "Ciphertext is too big to be decrypted";
		case Cryptography::DecryptResult::PlaintextBufferTooSmall:
			return "Plaintext buffer is too small to fit the result";
		case Cryptography::DecryptResult::PlaintextBufferTooBig:
			return "Plaintext buffer is bigger than expected";
		case Cryptography::DecryptResult::IncorrectEncryptionKey:
			return "Encryption key is not valid (empty)";
		case Cryptography::DecryptResult::PartiallyOverlappingBuffers:
			return "Plaintext and ciphertext buffers are not allowed to partially oveerlap";
		case Cryptography::DecryptResult::NoEncryptionKey:
			return "No encryption key was provided";
		case Cryptography::DecryptResult::NonceExhausted:
			return "Nonce has been exhausted, can't send any more data in this stream";
		}

		return "Unreachable code reached";
	}

	void closeSocket(const RawSocket socket)
	{
#if _WIN32
		shutdown(socket, SD_BOTH);
		closesocket(socket);
#else
		shutdown(socket, SHUT_RDWR);
		close(socket);
#endif
	}
} // namespace Network
