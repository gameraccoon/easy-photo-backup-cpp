// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/nsd/nsd_server.h"

#if _WIN32
#include <winsock32.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <bit>
#include <cstring>
#include <format>
#include <ranges>
#include <string>

#include "common_shared/nsd/utils_internal.h"

namespace NsdServer
{
	static uint16_t checksum16(const std::span<std::byte>& data)
	{
		// this is a very trivial checksum, eventually we want crc16 here
		uint16_t checksum = 0;
		for (uint16_t i = 0; i < data.size(); ++i)
		{
			checksum ^= static_cast<uint16_t>(data[i]) << ((i & 0x1) * 8);
		}
		return checksum;
	}

	static void writeBigEndian(std::vector<std::byte>& outVec, const uint16_t value)
	{
		if constexpr (std::endian::native == std::endian::little)
		{
			// ReSharper disable once CppDFAUnreachableCode
			outVec.push_back(static_cast<std::byte>((value & 0xff00) >> 8));
			outVec.push_back(static_cast<std::byte>(value & 0xff));
		}
		else
		{
			// ReSharper disable once CppDFAUnreachableCode
			outVec.push_back(static_cast<std::byte>(value & 0xff));
			outVec.push_back(static_cast<std::byte>((value & 0xff00) >> 8));
		}
	}

	ListenResult listen(
		const char* interfaceAddressStr,
		const NsdUtils::AddressType addressType,
		const uint16_t port,
		const char* serviceIdentifier,
		const uint16_t advertizedPort,
		const std::vector<std::byte>& extraData
	)
	{
		using namespace NsdInternalUtils;

		if (serviceIdentifier == nullptr)
		{
			return "service identifier can't be nullptr";
		}

		std::variant<int, std::string> result = createAndBindSocket(
			SocketType::NsdListen,
			interfaceAddressStr,
			addressType,
			port
		);

		if (std::holds_alternative<std::string>(result))
		{
			return std::get<std::string>(result);
		}

		const AutoclosingSocket socket = AutoclosingSocket(std::get<int>(std::move(result)));

		const std::string expectedPacket = std::format("aloha:{}\n", serviceIdentifier);
		if (expectedPacket.size() > 1024)
		{
			return std::format("Service ID is too long, maximum size is 1017 bytes, the ID length was {} bytes instead.", expectedPacket.size());
		}

		const size_t responseSize = 1 + 2 + 2 + extraData.size() + 2;
		if (responseSize > std::numeric_limits<uint16_t>::max())
		{
			return std::format("Response size is too big, maximum size is 65535 bytes, the data size was {} bytes instead.", responseSize);
		}

		std::vector<std::byte> response;
		response.reserve(responseSize);
		response.push_back(static_cast<std::byte>(0x01)); // protocol version
		writeBigEndian(response, static_cast<uint16_t>(extraData.size())); // size of extra data
		writeBigEndian(response, advertizedPort); // port
		std::ranges::copy(extraData, std::back_inserter(response)); // extra data
		writeBigEndian(response, checksum16(std::span(response.begin() + 3, response.end()))); // checksum

		if (response.size() != responseSize)
		{
			return std::format("The actual size of response is {} bytes, expected {} bytes.", response.size(), responseSize);
		}

		constexpr size_t BUFFER_SIZE = 1024;
		char buf[BUFFER_SIZE];
		ssize_t messageLength;
		sockaddr clientAddr;
		socklen_t clientAddrLen = sizeof(clientAddr);
		while ((messageLength = recvfrom(socket, buf, BUFFER_SIZE, 0, &clientAddr, &clientAddrLen)) != -1)
		{
			if (messageLength != expectedPacket.size())
			{
				continue;
			}

			if (std::memcmp(buf, expectedPacket.data(), expectedPacket.size()) != 0)
			{
				continue;
			}

			{
				const ssize_t sentSize = sendto(socket, response.data(), responseSize, 0, &clientAddr, clientAddrLen);
				if (sentSize == -1)
				{
					return std::format("Failed to send response to UDP socket, error code {} '{}'.", errno, strerror(errno));
				}
			}
		}

		return std::format("Failed to receive from UDP socket, error code {} '{}'.", errno, strerror(errno));
	}
} // namespace NsdServer
