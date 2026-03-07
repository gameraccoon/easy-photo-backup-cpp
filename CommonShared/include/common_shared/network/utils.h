// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>

namespace Network
{
	enum class AddressType : uint8_t
	{
		IpV4,
		IpV6,
	};

	struct NetworkAddress
	{
		std::string ip;
		uint16_t port = 0;
		AddressType addressType = AddressType::IpV4;
	};

	enum class SocketType : uint8_t
	{
		Tcp,
		Udp
	};

	std::variant<NetworkAddress, std::string> parseAddress(const void* addr, size_t addrLen);

	[[nodiscard]]
	std::variant<int, std::string> createSocket(SocketType type, AddressType addressType);
	std::optional<std::string> setSocketOption(int socket, int optionName);
	std::optional<std::string> setSocketTimeout(int socket, int optionName, int seconds, int microseconds);
	std::variant<uint16_t, std::string> getSocketPort(int socket);
	std::variant<NetworkAddress, std::string> getSocketAddress(int socket);
	std::optional<std::string> bindSocket(int socket, const char* interfaceAddressStr, AddressType addressType, uint16_t port);
	std::optional<std::string> connectToServer(int socket, const char* address, AddressType addressType, uint16_t port);
	std::optional<std::string> send(int socket, std::span<std::byte> data);
	void closeSocket(int socket);

	class AutoclosingSocket
	{
	public:
		explicit AutoclosingSocket(const int socket) noexcept
			: mSocket(socket) {}
		AutoclosingSocket(AutoclosingSocket&) = delete;
		AutoclosingSocket& operator=(AutoclosingSocket&) = delete;
		AutoclosingSocket(AutoclosingSocket&&) = delete;
		AutoclosingSocket& operator=(AutoclosingSocket&&) = delete;
		~AutoclosingSocket() { closeSocket(mSocket); }

		// ReSharper disable once CppNonExplicitConversionOperator
		operator int() const noexcept { return mSocket; }

	private:
		int mSocket;
	};
} // namespace Network
