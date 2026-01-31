// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>

#include "common_shared/nsd/shared_types.h"

namespace NsdInternalUtils
{
	enum class SocketType
	{
		NsdListen,
		Broadcast,
	};

	std::optional<std::string> parseAddress(const void* addr, size_t addrLen, std::string& outIp, uint16_t& outPort);

	[[nodiscard]]
	std::variant<int, std::string> createSocket(SocketType type, NsdTypes::AddressType addressType);
	std::optional<std::string> bindSocket(int socket, const char* interfaceAddressStr, NsdTypes::AddressType addressType, uint16_t port);
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

	[[nodiscard]]
	uint16_t checksum16v1(const std::span<std::byte>& data);
} // namespace NsdInternalUtils
