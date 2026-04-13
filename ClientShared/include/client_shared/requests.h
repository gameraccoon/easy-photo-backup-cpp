// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <variant>

#include "common_shared/network/protocol.h"
#include "common_shared/network/utils.h"

#include "client_shared/request_answers.h"

namespace Requests
{
	using namespace Protocol::Requests;

	using Request = std::variant<
		GetProtocolVersion,
		GetServerName>;

	[[nodiscard]] RequestAnswers::RequestAnswer prepareConnectionAndProcess(const char* serverAddress, const Network::AddressType serverAddressType, uint16_t port, const std::function<RequestAnswers::RequestAnswer(Network::RawSocket socket)>& processFn);

	[[nodiscard]] RequestAnswers::RequestAnswer sendAndProcessRequest(const char* serverAddress, const Network::AddressType serverAddressType, uint16_t port, Request&& request);
}
