// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <format>
#include <numeric>

#include "tests/helper_utils.h"
#include <gtest/gtest.h>

#include "common_shared/cryptography/noise/cipher_utils.h"
#include "common_shared/network/protocol.h"

#include "client_shared/file_send_utils.h"
#include "server_shared/file_receive_utils.h"

TEST(FileSendReceiveUtils, SendNoFiles_SendsOneChunkOfZeros)
{
	bool sendBufferCalled = false;
	bool isFileOpenCalled = false;
	bool getFileLengthCalled = false;
	FileSendUtils::Mocks sendMocks{
		.getAllFiles = [](std::vector<std::filesystem::path>&) {
			// do nothing
		},
		.openFile = [](std::ifstream&, const std::filesystem::path&) { FAIL(); },
		.getFileLength = [&getFileLengthCalled](std::ifstream&) -> size_t { getFileLengthCalled = true; return 0; },
		.isFileOpen = [&isFileOpenCalled](std::ifstream&) -> bool { isFileOpenCalled = true; return false; },
		.readFileStreamIntoSpan = [](std::ifstream&, std::span<std::byte>) { FAIL(); },
		.sendBuffer = [&sendBufferCalled](Network::RawSocket socket, std::span<std::byte> buffer, size_t size, Noise::CipherStateSending&) -> std::optional<std::string> {
			EXPECT_EQ(socket, Network::RawSocket(0));
			EXPECT_TRUE(std::all_of(buffer.begin(), buffer.end(), [](std::byte v) { return v == std::byte(0); }));
			EXPECT_EQ(buffer.size(), Protocol::FileExchange::ChunkSize + Cryptography::CipherAuthDataSize);
			EXPECT_EQ(size, Protocol::FileExchange::ChunkSize);
			sendBufferCalled = true;
			return std::nullopt;
		},
	};

	Noise::CipherStateSending cipherStateSending;
	vectorToArray(hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), cipherStateSending.cipherKey.raw);
	Noise::CipherStateReceiving cipherStateReceiving;
	cipherStateReceiving.cipherKey = cipherStateSending.cipherKey.clone();

	FileSendUtils::sendDirectory("", 0, cipherStateSending, cipherStateReceiving, sendMocks);

	EXPECT_TRUE(sendBufferCalled);
	EXPECT_FALSE(isFileOpenCalled);
	EXPECT_FALSE(getFileLengthCalled);
}

TEST(FileSendReceiveUtils, ReceiveChunkOfZeros_SaveNoFiles)
{
	bool recvBufferCalled = false;
	FileReceiveUtils::Mocks receiveMocks{
		.recvBuffer = [&recvBufferCalled](Network::RawSocket, std::span<std::byte> buffer, size_t& bytesReceived, Noise::CipherStateReceiving&) -> std::optional<std::string> {
			buffer = {};
			bytesReceived = Protocol::FileExchange::ChunkSize;
			recvBufferCalled = true;
			return std::nullopt;
		},
		.openFile = [](std::ofstream&, const std::filesystem::path&) { FAIL(); },
		.isFileOpen = [](std::ofstream&) -> bool { return false; },
		.writeSpanIntoStream = [](std::ofstream&, std::span<const std::byte>) { FAIL(); },
	};

	Noise::CipherStateSending cipherStateSending;
	vectorToArray(hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), cipherStateSending.cipherKey.raw);
	Noise::CipherStateReceiving cipherStateReceiving;
	cipherStateReceiving.cipherKey = cipherStateSending.cipherKey.clone();

	FileReceiveUtils::receiveFiles("", 0, cipherStateSending, cipherStateReceiving, receiveMocks);

	EXPECT_TRUE(recvBufferCalled);
}

TEST(FileSendReceiveUtils, RoundtripSendAndReceiveTwentyFiles)
{
	std::vector<std::filesystem::path> paths;
	constexpr const size_t NumberOfFiles = 20;
	paths.reserve(NumberOfFiles);
	for (size_t i = 0; i < NumberOfFiles; ++i)
	{
		paths.push_back(std::format("path{}", i));
	}
	std::array<size_t, NumberOfFiles> sizes{
		// try out sizes differently alligned to the 1024 chunk size (with metadata size of 10 + file name)
		size_t(1024 - (10 + 5) - 1), // -1 "path1"
		size_t(1024 - (10 + 5) + 1), // 0 "path2"
		size_t(1024 - (10 + 5) + 0), // 0 "path3"
		size_t(1024 - (10 + 5) + 1), // +1 "path4"
		size_t(1024 - (10 + 5) + 1), // +2 "path5"
		size_t(1024 - (10 + 5) + 3), // +5 "path6"
		size_t(1024 - (10 + 5) + 3), // +8 "path7"
		size_t(1024 - (10 + 5) + 2), // +10 "path8"
		size_t(1024 - (10 + 5) + 1), // +11 "path9"
		// try out some odd sizes
		size_t(1),
		size_t(0),
		size_t(8),
		size_t(2),
		size_t(13),
		size_t(3),
		size_t(64),
		size_t(128),
		size_t(10000),
		size_t(5),
		size_t(23),
	};
	ASSERT_EQ(paths.size(), sizes.size());
	const size_t totalFileSize = std::accumulate(sizes.begin(), sizes.end(), size_t(0));

	std::vector<std::byte> rawData;
	rawData.reserve(totalFileSize + (totalFileSize / Protocol::FileExchange::ChunkSize + 1) * Cryptography::CipherAuthDataSize + NumberOfFiles * 10);
	size_t readPosition = 0;
	int fileToWriteIdx = -1;

	std::vector<std::vector<std::byte>> outFileContents;

	bool getAllFilesCalled = false;
	FileSendUtils::Mocks sendMocks{
		.getAllFiles = [&paths, &getAllFilesCalled](std::vector<std::filesystem::path>& files) {
			EXPECT_FALSE(getAllFilesCalled);
			files = paths;
			getAllFilesCalled = true; },
		.openFile = [&paths, &fileToWriteIdx](std::ifstream&, const std::filesystem::path& path) {
			EXPECT_NE(std::find(paths.begin(), paths.end(), path), paths.end());
			++fileToWriteIdx; },
		.getFileLength = [&sizes, &fileToWriteIdx](std::ifstream&) -> size_t { return sizes[fileToWriteIdx]; },
		.isFileOpen = [](std::ifstream&) -> bool { return true; },
		.readFileStreamIntoSpan = [&fileToWriteIdx](std::ifstream&, std::span<std::byte> buffer) { std::fill(buffer.begin(), buffer.end(), std::byte(fileToWriteIdx)); },
		.sendBuffer = [&rawData](Network::RawSocket, std::span<std::byte> buffer, size_t bytesToWrite, Noise::CipherStateSending& sendingState) -> std::optional<std::string> {
			EXPECT_EQ(buffer.size(), Protocol::FileExchange::ChunkSize + Cryptography::CipherAuthDataSize);
			EXPECT_EQ(bytesToWrite, Protocol::FileExchange::ChunkSize);
			EXPECT_EQ(Noise::Utils::encryptTransportMessageInplace(sendingState, buffer), Cryptography::EncryptResult::Success);
			std::copy(buffer.begin(), buffer.begin() + buffer.size(), std::back_inserter(rawData));
			return std::nullopt;
		},
	};
	FileReceiveUtils::Mocks receiveMocks{
		.recvBuffer = [&rawData, &readPosition](Network::RawSocket, std::span<std::byte> buffer, size_t& bytesReceived, Noise::CipherStateReceiving& receivingState) -> std::optional<std::string> {
			constexpr const size_t BytesToRead = Protocol::FileExchange::ChunkSize + Cryptography::CipherAuthDataSize;
			constexpr const size_t BytesToReturn = Protocol::FileExchange::ChunkSize;
			EXPECT_EQ(buffer.size(), BytesToRead);
			std::copy(rawData.begin() + readPosition, rawData.begin() + readPosition + BytesToRead, buffer.begin());
			EXPECT_EQ(Noise::Utils::decryptTransportMessageInplace(receivingState, std::span<std::byte>(buffer.data(), BytesToRead)), Cryptography::DecryptResult::Success);
			readPosition += BytesToRead;
			EXPECT_LE(readPosition, rawData.size());
			bytesReceived = BytesToReturn;
			return std::nullopt;
		},
		.openFile = [&paths, &outFileContents](std::ofstream&, const std::filesystem::path& path) {
			const size_t i = outFileContents.size();
			outFileContents.emplace_back();
			ASSERT_LT(i, paths.size());
			EXPECT_EQ(paths[i], path); },
		.isFileOpen = [](std::ofstream&) -> bool { return true; },
		.writeSpanIntoStream = [&outFileContents](std::ofstream&, std::span<const std::byte> buffer) {
			ASSERT_FALSE(outFileContents.empty());
			std::copy(buffer.begin(), buffer.end(), std::back_inserter(outFileContents.back())); },
	};

	Noise::CipherStateSending cipherStateSending;
	vectorToArray(hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), cipherStateSending.cipherKey.raw);
	Noise::CipherStateReceiving cipherStateReceiving;
	cipherStateReceiving.cipherKey = cipherStateSending.cipherKey.clone();

	// for now do it sequentially, in the future we would need to run it in two threads
	FileSendUtils::sendDirectory("", 0, cipherStateSending, cipherStateReceiving, sendMocks);
	FileReceiveUtils::receiveFiles("", 0, cipherStateSending, cipherStateReceiving, receiveMocks);

	EXPECT_TRUE(getAllFilesCalled);
	EXPECT_EQ(readPosition, rawData.size());

	ASSERT_EQ(outFileContents.size(), sizes.size());
	for (size_t i = 0; i < outFileContents.size(); ++i)
	{
		EXPECT_EQ(outFileContents[i].size(), sizes[i]);
		EXPECT_TRUE(std::all_of(outFileContents[i].begin(), outFileContents[i].end(), [i](std::byte v) { return v == std::byte(i); }));
	}
}
