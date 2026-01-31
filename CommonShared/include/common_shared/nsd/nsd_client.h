// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <atomic>
#include <functional>
#include <optional>
#include <string>

#include "common_shared/nsd/shared_types.h"

namespace NsdClient
{
	using ListenResult = std::optional<std::string>;

	enum class DiscoveryState
	{
		Added,
		Removed,
	};

	struct ServiceAddress
	{
		std::string ip;
		uint16_t port;
	};

	struct DiscoveryResult
	{
		ServiceAddress address;
		std::vector<std::byte> extraData;
		DiscoveryState state;
	};

	ListenResult startServiceDiscoveryThread(
		const char* serviceIdentifier,
		uint16_t broadcastPort,
		NsdTypes::AddressType addressType,
		float broadcastPeriodSec,
		const std::function<void(DiscoveryResult&&)>& resultFunction,
		const std::atomic_bool& stopSignalReceiver
	);
} // namespace NsdClient
