// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <variant>

#include "common_shared/nsd/utils.h"

namespace NsdInternalUtils
{
	enum class SocketType
	{
		NsdListen,
		Broadcast,
	};

	[[nodiscard]]
	std::variant<int, std::string> createAndBindSocket(SocketType type, const char* interfaceAddressStr, NsdUtils::AddressType addressType, uint16_t port);
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
