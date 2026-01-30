// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <format>

#include "common_shared/debug/log.h"
#include "common_shared/nsd/nsd_server.h"

#include "server_shared/example/example.h"

int main()
{
	debug::log::printDebug(std::format("Hello, World! {}\n", example::EXAMPLE_SERVER_VALUE));
	example::printAnotherTestValue();

	const std::vector<std::byte> extraData{ {
		static_cast<std::byte>(1), // protocol id
		static_cast<std::byte>(0), // the rest is the server ID
		static_cast<std::byte>(1),
		static_cast<std::byte>(2),
		static_cast<std::byte>(3),
		static_cast<std::byte>(4),
		static_cast<std::byte>(5),
		static_cast<std::byte>(6),
		static_cast<std::byte>(7),
		static_cast<std::byte>(8),
		static_cast<std::byte>(9),
		static_cast<std::byte>(10),
		static_cast<std::byte>(11),
		static_cast<std::byte>(12),
		static_cast<std::byte>(13),
		static_cast<std::byte>(14),
		static_cast<std::byte>(15),
	} };

	NsdServer::ListenResult result = NsdServer::listen("0.0.0.0", NsdServer::AddressType::IpV4, 5354, "_easy-photo-backup._tcp", 2134, extraData);
	if (result.has_value())
	{
		debug::log::printDebug(std::format("NSD server error: '{}'", *result));
	}
	else
	{
		debug::log::printDebug("NSD server stopped without errors");
	}
	return 0;
}
