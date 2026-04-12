// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "common_shared/bstorage/storage.h"

#include <array>
#include <bit>
#include <fstream>
#include <iostream>

#include "common_shared/serialization/number_serialization.h"

namespace BStorage
{
	[[nodiscard]] std::optional<std::tuple<Value, uint16_t>> loadStorage(const std::filesystem::path& filePath) noexcept
	{
		std::ifstream filestream(filePath, std::ios::binary);
		if (!filestream)
		{
			return std::nullopt;
		}

		std::array<char, 2> versionBytes = {};
		filestream.read(versionBytes.data(), versionBytes.size());
		uint16_t version = Serialization::readUint16(std::bit_cast<std::byte>(versionBytes[0]), std::bit_cast<std::byte>(versionBytes[1]));

		std::optional<Value> newValue = Value::readFromStream(filestream);
		if (!newValue.has_value())
		{
			return std::nullopt;
		}

		return std::make_tuple(std::move(*newValue), version);
	}

	bool saveStorage(const std::filesystem::path& filePath, const Value& storage, uint16_t version) noexcept
	{
		std::ofstream filestream(filePath, std::ios::binary);
		if (!filestream)
		{
			return false;
		}

		std::array<std::byte, 2> versionBytes = {};
		Serialization::writeUint16(versionBytes[0], versionBytes[1], version);
		filestream.write(reinterpret_cast<char*>(versionBytes.data()), versionBytes.size());

		return storage.writeToStream(filestream);
	}
} // namespace BStorage
