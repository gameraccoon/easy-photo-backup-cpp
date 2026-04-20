// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <span>

#include "common_shared/network/utils.h"

namespace Requests
{
	void processPairingInteractiveRequest(std::span<const std::byte> firstMessage, const Network::RawSocket socket);
}
