// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <format>

#include "common_shared/debug/log.h"
#include "common_shared/nsd/nsd_client.h"

#include "client_shared/example/example.h"

int main()
{
	debug::log::printDebug(std::format("Hello, World! {}\n", example::EXAMPLE_CLIENT_VALUE));
	example::printAnotherTestValue();

	std::optional<std::string> result = NsdClient::startServiceDiscoveryThread(
		"_easy-photo-backup._tcp",
		5354,
		NsdTypes::AddressType::IpV4,
		1,
		[](auto&& event) {
			if (event.state == NsdClient::DiscoveryState::Added)
			{
				int version = -1;
				if (!event.extraData.empty())
				{
					version = static_cast<int>(event.extraData[0]);
				}

				std::string idString;
				idString.reserve(event.extraData.size());
				for (std::byte b : event.extraData)
				{
					idString.push_back(static_cast<int>(b) + '0');
				}

				debug::log::printDebug(std::format("Server added v={}, id='{}'", version, idString));
			}
			else
			{
				debug::log::printDebug("Server removed");
			}
		},
		std::atomic_bool{}
	);

	if (result.has_value())
	{
		debug::log::printDebug(std::format("NSD client error: '{}'", *result));
	}
	else
	{
		debug::log::printDebug("NSD client stopped without errors");
	}
	return 0;
}
