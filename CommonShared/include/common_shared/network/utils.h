// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>

#if _WIN32
#include <basetsd.h>
#endif

namespace Network
{
#if _WIN32
	using RawSocket = UINT_PTR;
#else
	using RawSocket = int;
#endif

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
	std::variant<RawSocket, std::string> createSocket(SocketType type, AddressType addressType);
	std::optional<std::string> setSocketOption(RawSocket socket, int optionName);
	std::optional<std::string> setSocketTimeout(RawSocket socket, int optionName, int seconds, int microseconds);
	std::variant<uint16_t, std::string> getSocketPort(RawSocket socket);
	std::variant<NetworkAddress, std::string> getSocketAddress(RawSocket socket);
	std::optional<std::string> bindSocket(RawSocket socket, const char* interfaceAddressStr, AddressType addressType, uint16_t port);
	std::optional<std::string> connectToServer(RawSocket socket, const char* address, AddressType addressType, uint16_t port);
	std::optional<std::string> send(RawSocket socket, std::span<const std::byte> data);
	// if the result is std::nullopt, receivedBytes is guaranteed to be greater than 0 and less than outData.size()
	std::optional<std::string> recv(RawSocket socket, std::span<std::byte> outData, size_t& receivedBytes);
	void closeSocket(RawSocket socket);

	class AutoclosingSocket
	{
	public:
		explicit AutoclosingSocket(const RawSocket socket) noexcept
			: mSocket(socket) {}
		AutoclosingSocket(AutoclosingSocket&) = delete;
		AutoclosingSocket& operator=(AutoclosingSocket&) = delete;
		AutoclosingSocket(AutoclosingSocket&&) = delete;
		AutoclosingSocket& operator=(AutoclosingSocket&&) = delete;
		~AutoclosingSocket() { closeSocket(mSocket); }

		// ReSharper disable once CppNonExplicitConversionOperator
		operator RawSocket() const noexcept { return mSocket; }

	private:
		RawSocket mSocket;
	};
} // namespace Network
