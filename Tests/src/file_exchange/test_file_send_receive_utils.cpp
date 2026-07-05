// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include <algorithm>
#include <chrono>
#include <format>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <thread>

#include "tests/assert_helper.h"
#include "tests/helper_utils.h"
#include <gtest/gtest.h>

#include "common_shared/cryptography/noise/cipher_utils.h"
#include "common_shared/cryptography/primitives/hash_functions.h"
#include "common_shared/cryptography/utils/random.h"
#include "common_shared/network/protocol.h"

#include "client_shared/file_send_utils.h"
#include "server_shared/file_receive_utils.h"

// a simple test implementation of a message pipe (can be slow, but should be simple to review)
template<size_t Size>
class TestMessagePipe
{
public:
	void push(std::span<const std::byte> buffer) noexcept
	{
		ASSERT_EQ(buffer.size(), Size);
		if (buffer.size() != Size)
		{
			return;
		}

		std::lock_guard l(mMessagesMutex);

		mMessages.push(vectorToArray<Size>(buffer));
	}

	std::optional<std::array<std::byte, Size>> pop() noexcept
	{
		const auto timeStart = std::chrono::steady_clock::now();
		// one second timeout
		while (std::chrono::steady_clock::now() - timeStart < std::chrono::seconds(1))
		{
			std::unique_lock l(mMessagesMutex);
			if (mMessages.empty())
			{
				l.unlock();
				std::this_thread::yield();
				continue;
			}

			std::array<std::byte, Size> result = mMessages.front();
			mMessages.pop();
			return result;
		}

		return std::nullopt;
	}

	size_t size() noexcept
	{
		std::lock_guard l(mMessagesMutex);
		return mMessages.size();
	}

private:
	std::mutex mMessagesMutex;
	std::queue<std::array<std::byte, Size>> mMessages;
};

struct TestFileExchangeFile
{
	std::filesystem::path path;
	std::vector<std::byte> data;

	TestFileExchangeFile clone() const noexcept
	{
		return TestFileExchangeFile{
			.path = path,
			.data = data,
		};
	}

	bool operator==(const TestFileExchangeFile& other) const
	{
		if (path != other.path)
		{
			return false;
		}

		if (data.size() != other.data.size())
		{
			return false;
		}

		for (size_t i = 0; i < data.size(); ++i)
		{
			if (data[i] != other.data[i])
			{
				return false;
			}
		}

		return true;
	}
};

static std::vector<TestFileExchangeFile> cloneTestFiles(const std::vector<TestFileExchangeFile>& source)
{
	std::vector<TestFileExchangeFile> result;
	result.reserve(source.size());
	for (const TestFileExchangeFile& item : source)
	{
		result.push_back(item.clone());
	}
	return result;
}

static void expectTwoArraysEqual(std::vector<TestFileExchangeFile> a, std::vector<TestFileExchangeFile> b)
{
	ASSERT_EQ(a.size(), b.size());

	std::sort(a.begin(), a.end(), [](const TestFileExchangeFile& a, const TestFileExchangeFile& b) {
		return a.path < b.path;
	});

	std::sort(b.begin(), b.end(), [](const TestFileExchangeFile& a, const TestFileExchangeFile& b) {
		return a.path < b.path;
	});

	for (size_t i = 0; i < a.size(); ++i)
	{
		if (a[i].path != b[i].path)
		{
			ADD_FAILURE() << std::format("a[{}].path != b[{}].path, values are '{}' and '{}'", i, i, a[i].path.string(), b[i].path.string());
		}
		else if (a[i].data != b[i].data)
		{
			EXPECT_EQ(a[i].data.size(), b[i].data.size());
			ADD_FAILURE() << std::format("a[{}].data != b[{}].data for file '{}'", i, i, a[i].path.string());
			for (size_t dataIdx = 0; dataIdx < a[i].data.size(); ++dataIdx)
			{
				if (a[i].data[dataIdx] != b[i].data[dataIdx])
				{
					Debug::Log::printDebug("First diverged byte at index {}", dataIdx);
					break;
				}
			}
		}
	}
}

static std::vector<std::byte> generateTestFileData(size_t size, std::minstd_rand::result_type seed)
{
	std::minstd_rand random;
	random.seed(seed);

	std::vector<std::byte> result;
	result.resize(size);
	for (size_t i = 0; i < size; ++i)
	{
		result[i] = std::byte(random() % 256);
	}
	return result;
}

static std::minstd_rand::result_type getRandomSeed() noexcept
{
	return static_cast<std::minstd_rand::result_type>(time(nullptr));
}

struct FileExchangeTestInstructions
{
	size_t breakFileSendPipeAfterBytes = std::numeric_limits<size_t>::max();
	std::vector<TestFileExchangeFile> existingFiles = {};
	std::vector<std::string> expectedOverriddenFiles = {};
	std::optional<std::byte> corruptReceivedFilesPattern = {};
	bool checkNoFilesWritten = false;
};

struct FileExchangeTestResult
{
	std::vector<TestFileExchangeFile> totalReceivedFiles = {};
};

static FileExchangeTestResult runFileExchangeTest(ClientStorage& clientStorage, const std::vector<TestFileExchangeFile>& filesToSend, std::vector<TestFileExchangeFile> expectedFilesToReceive, const std::vector<TestFileExchangeFile>& expectedFilesToConfirm, const FileExchangeTestInstructions& instructions = {})
{
	Cryptography::CipherKey cipherKeyFromSenderToReceiver;
	Cryptography::fillWithRandomBytes(cipherKeyFromSenderToReceiver);
	Cryptography::CipherKey cipherKeyFromReceiverToSender;
	Cryptography::fillWithRandomBytes(cipherKeyFromReceiverToSender);

	TestMessagePipe<Protocol::FileExchange::ChunkSize + Cryptography::CipherAuthDataSize> fileMessages;
	TestMessagePipe<Protocol::FileExchange::AnswerChunkSize + Cryptography::CipherAuthDataSize> answerMessages;

	auto sendingThread = std::thread([&filesToSend, &fileMessages, &answerMessages, &cipherKeyFromSenderToReceiver, &cipherKeyFromReceiverToSender, &clientStorage, &instructions]() {
		int fileToWriteIdx = -1;
		size_t bytesWritten = 0;
		size_t fileCursor = 0;
		bool getAllFilesCalled = false;
		FileSendUtils::Mocks sendMocks{
			.getAllFiles = [&filesToSend, &getAllFilesCalled](std::vector<std::filesystem::path>& files) {
				EXPECT_FALSE(getAllFilesCalled); // expected to be called only once
				files.reserve(filesToSend.size());
				for (const TestFileExchangeFile& file : filesToSend)
				{
					files.push_back(file.path);
				}
				getAllFilesCalled = true;
			},
			.openFile = [&filesToSend, &fileToWriteIdx, &fileCursor](std::ifstream&, size_t cursor, const std::filesystem::path& path) {
				auto it = std::find_if(filesToSend.begin(), filesToSend.end(), [&path](const TestFileExchangeFile& file) {
					return file.path == path;
				});

				if (it == filesToSend.end())
				{
					return;
				}

				fileToWriteIdx = static_cast<int>(std::distance(filesToSend.begin(), it));
				fileCursor = cursor;
			},
			.getFileLength = [&filesToSend, &fileToWriteIdx](std::ifstream&) -> uint64_t {
				return static_cast<uint64_t>(filesToSend[fileToWriteIdx].data.size());
			},
			.isFileOpen = [](std::ifstream&) -> bool {
				return true;
			},
			.seek = [&fileCursor](std::ifstream&, size_t position) -> void {
				fileCursor = position;
			},
			.calculateFileHash = [&filesToSend, &fileToWriteIdx](std::ifstream&, size_t size, Cryptography::HashResult& result) -> int {
				if (size > filesToSend[fileToWriteIdx].data.size())
				{
					return -1;
				}
				Cryptography::hashSpan(filesToSend[fileToWriteIdx].data, result);
				Cryptography::hashSpan(std::span<const std::byte>(filesToSend[fileToWriteIdx].data.data(), size), result);
				return 0;
			},
			.readFileStreamIntoSpan = [&filesToSend, &fileToWriteIdx, &fileCursor](std::ifstream&, std::span<std::byte> buffer) {
				ASSERT_LE(fileCursor, filesToSend[fileToWriteIdx].data.size());
				std::copy(filesToSend[fileToWriteIdx].data.data() + fileCursor, filesToSend[fileToWriteIdx].data.data() + fileCursor + buffer.size(), buffer.data());
				fileCursor += buffer.size();
			},
			.sendBuffer = [&fileMessages, &bytesWritten, &instructions](Network::RawSocket, std::span<std::byte> buffer, size_t bytesToWrite, Noise::CipherStateSending& sendingState) -> std::optional<std::string> {
				EXPECT_EQ(buffer.size(), Protocol::FileExchange::ChunkSize + Cryptography::CipherAuthDataSize);
				EXPECT_EQ(bytesToWrite, Protocol::FileExchange::ChunkSize);
				EXPECT_EQ(Noise::Utils::encryptTransportMessageInplace(sendingState, buffer), Cryptography::EncryptResult::Success);
				fileMessages.push(buffer);

				bytesWritten += bytesToWrite;
				if (bytesWritten > instructions.breakFileSendPipeAfterBytes)
				{
					return "Pipe is broken as per test request";
				}
				return std::nullopt;
			},
			.recvAnswerBuffer = [&answerMessages](Network::RawSocket, std::span<std::byte> buffer, size_t& bytesReceived, Noise::CipherStateReceiving& receivingState) -> std::optional<std::string> {
				constexpr const size_t BytesToRead = Protocol::FileExchange::AnswerChunkSize + Cryptography::CipherAuthDataSize;
				constexpr const size_t BytesToReturn = Protocol::FileExchange::AnswerChunkSize;
				EXPECT_EQ(buffer.size(), BytesToRead);
				std::optional<std::array<std::byte, BytesToRead>> receivedBytes = answerMessages.pop();
				if (!receivedBytes.has_value())
				{
					return "Timeout on reading from stream";
				}
				EXPECT_EQ(receivedBytes->size(), buffer.size());
				std::copy(receivedBytes->begin(), receivedBytes->end(), buffer.begin());
				if (auto result = Noise::Utils::decryptTransportMessageInplace(receivingState, std::span<std::byte>(buffer.data(), BytesToRead)); result != Cryptography::DecryptResult::Success)
				{
					return std::format("Could not decode the message from the stream: {}", static_cast<int>(result));
				}

				bytesReceived = BytesToReturn;
				return std::nullopt;
			}
		};

		Noise::CipherStateSending cipherStateSending;
		cipherStateSending.cipherKey = cipherKeyFromSenderToReceiver.clone();
		Noise::CipherStateReceiving cipherStateReceiving;
		cipherStateReceiving.cipherKey = cipherKeyFromReceiverToSender.clone();

		FileSendUtils::sendDirectory("", "", 0, clientStorage, cipherStateSending, cipherStateReceiving, sendMocks);

		EXPECT_TRUE(getAllFilesCalled);
	});

	std::vector<TestFileExchangeFile> receivedFiles = cloneTestFiles(instructions.existingFiles);
	receivedFiles.reserve(receivedFiles.size() + filesToSend.size());
	size_t bytesRead = 0;

	FileReceiveUtils::Mocks receiveMocks{
		.recvBuffer = [&fileMessages, &instructions, &bytesRead](Network::RawSocket, std::span<std::byte> buffer, size_t& bytesReceived, Noise::CipherStateReceiving& receivingState) -> std::optional<std::string> {
			constexpr const size_t BytesToRead = Protocol::FileExchange::ChunkSize + Cryptography::CipherAuthDataSize;
			constexpr const size_t BytesToReturn = Protocol::FileExchange::ChunkSize;
			EXPECT_EQ(buffer.size(), BytesToRead);
			std::optional<std::array<std::byte, BytesToRead>> receivedBytes = fileMessages.pop();
			if (!receivedBytes.has_value())
			{
				return "Timeout on reading from stream";
			}
			std::copy(receivedBytes->begin(), receivedBytes->end(), buffer.begin());
			if (auto result = Noise::Utils::decryptTransportMessageInplace(receivingState, std::span<std::byte>(buffer.data(), BytesToRead)); result != Cryptography::DecryptResult::Success)
			{
				return std::format("Could not decode the message from the stream: {}", static_cast<int>(result));
			}

			bytesRead += BytesToReturn;
			if (bytesRead > instructions.breakFileSendPipeAfterBytes)
			{
				return "Pipe is broken as per test request";
			}

			bytesReceived = BytesToReturn;
			return std::nullopt;
		},
		.isFileExists = [&receivedFiles](const std::filesystem::path& path) {
			return std::find_if(receivedFiles.begin(), receivedFiles.end(), [&path](const TestFileExchangeFile& file) {
					   return file.path == path;
				   })
				!= receivedFiles.end();
		},
		.openFile = [&receivedFiles, &instructions](std::ofstream&, size_t cursor, const std::filesystem::path& path) {
			if (auto it = std::find_if(receivedFiles.begin(), receivedFiles.end(), [path](const TestFileExchangeFile& file) {
					return file.path == path;
				});
				it != receivedFiles.end())
			{
				ASSERT_NE(std::find(instructions.expectedOverriddenFiles.begin(), instructions.expectedOverriddenFiles.end(), path), instructions.expectedOverriddenFiles.end());
				std::swap(receivedFiles.back(), *it);
			}
			else
			{
				ASSERT_EQ(std::find(instructions.expectedOverriddenFiles.begin(), instructions.expectedOverriddenFiles.end(), path), instructions.expectedOverriddenFiles.end());
				receivedFiles.push_back(TestFileExchangeFile{
					.path = path,
					.data = {},
				});
			}

			ASSERT_LE(cursor, receivedFiles.back().data.size());
			receivedFiles.back().data.resize(cursor);
			ASSERT_FALSE(instructions.checkNoFilesWritten);
		},
		.isFileOpen = [](std::ofstream&) -> bool {
			return true;
		},
		.calculateFileHash = [&receivedFiles](const std::filesystem::path& path, int64_t size, Cryptography::HashResult& hashResult) -> int {
			auto it = std::find_if(receivedFiles.begin(), receivedFiles.end(), [&path](const TestFileExchangeFile& file) {
				return file.path == path;
			});

			if (it == receivedFiles.end())
			{
				return -1;
			}

			if (size == -1)
			{
				Cryptography::hashSpan(it->data, hashResult);
			}
			else
			{
				EXPECT_LT(static_cast<size_t>(size), it->data.size());
				if (static_cast<size_t>(size) < it->data.size())
				{
					Cryptography::hashSpan(std::span<std::byte>(it->data.begin(), it->data.begin() + size), hashResult);
				}
			}
			return 0;
		},
		.writeSpanIntoStream = [&receivedFiles, &instructions](std::ofstream&, std::span<const std::byte> buffer) {
			ASSERT_FALSE(receivedFiles.empty());
			ASSERT_FALSE(instructions.checkNoFilesWritten);
			if (instructions.corruptReceivedFilesPattern.has_value())
			{
				std::vector<std::byte>& fileBuffer = receivedFiles.back().data;
				fileBuffer.resize(fileBuffer.size() + buffer.size());
				std::fill(fileBuffer.begin() + (fileBuffer.size() - buffer.size()), fileBuffer.end(), *instructions.corruptReceivedFilesPattern);
			}
			else
			{
				std::copy(buffer.begin(), buffer.end(), std::back_inserter(receivedFiles.back().data));
			}
		},
		.sendAnswerBuffer = [&answerMessages](Network::RawSocket, std::span<std::byte> buffer, size_t bytesToWrite, Noise::CipherStateSending& sendingState) -> std::optional<std::string> {
			EXPECT_EQ(buffer.size(), Protocol::FileExchange::AnswerChunkSize + Cryptography::CipherAuthDataSize);
			EXPECT_EQ(bytesToWrite, Protocol::FileExchange::AnswerChunkSize);
			EXPECT_EQ(Noise::Utils::encryptTransportMessageInplace(sendingState, buffer), Cryptography::EncryptResult::Success);
			answerMessages.push(buffer);
			return std::nullopt;
		},
	};

	Noise::CipherStateSending cipherStateSending;
	cipherStateSending.cipherKey = cipherKeyFromReceiverToSender.clone();
	Noise::CipherStateReceiving cipherStateReceiving;
	cipherStateReceiving.cipherKey = cipherKeyFromSenderToReceiver.clone();

	FileReceiveUtils::receiveFiles("", 0, cipherStateSending, cipherStateReceiving, receiveMocks);
	sendingThread.join();

	EXPECT_EQ(size_t(0), fileMessages.size());
	EXPECT_EQ(size_t(0), answerMessages.size());

	expectTwoArraysEqual(receivedFiles, expectedFilesToReceive);

	clientStorage.read([&expectedFilesToConfirm](const ClientStorageData& storageData) {
		EXPECT_EQ(expectedFilesToConfirm.size(), storageData.sentFiles.size());
		for (const auto& expectedFile : expectedFilesToConfirm)
		{
			EXPECT_NE(std::find(storageData.sentFiles.begin(), storageData.sentFiles.end(), expectedFile.path), storageData.sentFiles.end()) << std::format("File '{}' expected to be confirmed but wasn't", expectedFile.path.string());
		}
	});

	return FileExchangeTestResult{
		.totalReceivedFiles = cloneTestFiles(receivedFiles),
	};
}

TEST(FileSendReceiveUtils, SendNoFiles_SendsOneChunkOfZeros)
{
	bool sendBufferCalled = false;
	bool isFileOpenCalled = false;
	bool getFileLengthCalled = false;
	bool readAnswerCalled = false;
	FileSendUtils::Mocks sendMocks{
		.getAllFiles = [](std::vector<std::filesystem::path>&) {
			// do nothing
		},
		.openFile = [](std::ifstream&, size_t, const std::filesystem::path&) {
			FAIL();
		},
		.getFileLength = [&getFileLengthCalled](std::ifstream&) -> uint64_t {
			getFileLengthCalled = true;
			return 0;
		},
		.isFileOpen = [&isFileOpenCalled](std::ifstream&) -> bool {
			isFileOpenCalled = true;
			return false;
		},
		.seek = [](std::ifstream&, size_t) -> void {
		},
		.calculateFileHash = [](std::ifstream&, size_t, Cryptography::HashResult& outHash) -> int {
			outHash = {};
			return 0;
		},
		.readFileStreamIntoSpan = [](std::ifstream&, std::span<std::byte>) {
			FAIL();
		},
		.sendBuffer = [&sendBufferCalled](Network::RawSocket socket, std::span<std::byte> buffer, size_t size, Noise::CipherStateSending&) -> std::optional<std::string> {
			EXPECT_EQ(socket, Network::RawSocket(0));
			EXPECT_TRUE(std::all_of(buffer.begin(), buffer.end(), [](std::byte v) {
				return v == std::byte(0);
			}));
			EXPECT_EQ(buffer.size(), Protocol::FileExchange::ChunkSize + Cryptography::CipherAuthDataSize);
			EXPECT_EQ(size, Protocol::FileExchange::ChunkSize);
			sendBufferCalled = true;
			return std::nullopt;
		},
		.recvAnswerBuffer = [&readAnswerCalled](Network::RawSocket, std::span<std::byte>, size_t&, Noise::CipherStateReceiving&) -> std::optional<std::string> {
			readAnswerCalled = true;
			return std::nullopt;
		},
	};

	Noise::CipherStateSending cipherStateSending;
	vectorToArray(hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), cipherStateSending.cipherKey.raw);
	Noise::CipherStateReceiving cipherStateReceiving;
	cipherStateReceiving.cipherKey = cipherStateSending.cipherKey.clone();

	ClientStorage storage = ClientStorage::testCreateEmpty();
	FileSendUtils::sendDirectory("", "", 0, storage, cipherStateSending, cipherStateReceiving, sendMocks);

	storage.read([](const ClientStorageData& storageData) {
		EXPECT_TRUE(storageData.sentFiles.empty());
		EXPECT_TRUE(storageData.partiallySentFiles.empty());
	});

	EXPECT_TRUE(sendBufferCalled);
	EXPECT_FALSE(isFileOpenCalled);
	EXPECT_FALSE(getFileLengthCalled);
	EXPECT_FALSE(readAnswerCalled);
}

TEST(FileSendReceiveUtils, ReceiveChunkOfZeros_SavedNoFiles)
{
	bool recvBufferCalled = false;
	bool sendAnswerCalled = false;
	FileReceiveUtils::Mocks receiveMocks{
		.recvBuffer = [&recvBufferCalled](Network::RawSocket, std::span<std::byte> buffer, size_t& bytesReceived, Noise::CipherStateReceiving&) -> std::optional<std::string> {
			buffer = {};
			bytesReceived = Protocol::FileExchange::ChunkSize;
			recvBufferCalled = true;
			return std::nullopt;
		},
		.isFileExists = [](const std::filesystem::path&) {
			return false;
		},
		.openFile = [](std::ofstream&, size_t, const std::filesystem::path&) {
			FAIL();
		},
		.isFileOpen = [](std::ofstream&) -> bool {
			return false;
		},
		.calculateFileHash = [](const std::filesystem::path&, size_t, Cryptography::HashResult& outHash) -> int {
			outHash = {};
			return 0;
		},
		.writeSpanIntoStream = [](std::ofstream&, std::span<const std::byte>) {
			FAIL();
		},
		.sendAnswerBuffer = [&sendAnswerCalled](Network::RawSocket, std::span<std::byte>, size_t, Noise::CipherStateSending&) -> std::optional<std::string> {
			sendAnswerCalled = true;
			return std::nullopt;
		},
	};

	Noise::CipherStateSending cipherStateSending;
	vectorToArray(hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), cipherStateSending.cipherKey.raw);
	Noise::CipherStateReceiving cipherStateReceiving;
	cipherStateReceiving.cipherKey = cipherStateSending.cipherKey.clone();

	FileReceiveUtils::receiveFiles("", 0, cipherStateSending, cipherStateReceiving, receiveMocks);

	EXPECT_TRUE(recvBufferCalled);
	EXPECT_FALSE(sendAnswerCalled);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveOneEmptyFile_SuccessfullyReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.push_back(TestFileExchangeFile{
		.path = std::format("empty.txt"),
		.data = {},
	});

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveOneTinyFile_SuccessfullyReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.push_back(TestFileExchangeFile{
		.path = "tiny.txt",
		.data = generateTestFileData(4, getRandomSeed()),
	});

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveOneSmallFile_SuccessfullyReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.push_back(TestFileExchangeFile{
		.path = "small.txt",
		.data = generateTestFileData(500, getRandomSeed()),
	});

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveOneMediumFile_SuccessfullyReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.push_back(TestFileExchangeFile{
		.path = "med.txt",
		.data = generateTestFileData(3000, getRandomSeed()),
	});

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveOneBigFile_SuccessfullyReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.push_back(TestFileExchangeFile{
		.path = "big.txt",
		.data = generateTestFileData(200000, getRandomSeed()),
	});

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveTwentyFiles_SuccessfullyReceived)
{
	const std::array<size_t, 20> sizes{
		// try out sizes differently alligned to the chunk size (with metadata size of 10 + file name)
		size_t(Protocol::FileExchange::ChunkSize - std::min(Protocol::FileExchange::ChunkSize, size_t((10 + 5) - 1))), // -1 "path1"
		size_t(Protocol::FileExchange::ChunkSize - std::min(Protocol::FileExchange::ChunkSize, size_t((10 + 5) + 1))), // 0 "path2"
		size_t(Protocol::FileExchange::ChunkSize - std::min(Protocol::FileExchange::ChunkSize, size_t((10 + 5) + 0))), // 0 "path3"
		size_t(Protocol::FileExchange::ChunkSize - std::min(Protocol::FileExchange::ChunkSize, size_t((10 + 5) + 1))), // +1 "path4"
		size_t(Protocol::FileExchange::ChunkSize - std::min(Protocol::FileExchange::ChunkSize, size_t((10 + 5) - 4))), // -3 "path5"
		size_t(Protocol::FileExchange::ChunkSize - std::min(Protocol::FileExchange::ChunkSize, size_t((10 + 5) - 3))), // -6 "path6"
		size_t(Protocol::FileExchange::ChunkSize - std::min(Protocol::FileExchange::ChunkSize, size_t((10 + 5) - 3))), // -9 "path7"
		size_t(Protocol::FileExchange::ChunkSize - std::min(Protocol::FileExchange::ChunkSize, size_t((10 + 5) - 1))), // -10 "path8"
		size_t(Protocol::FileExchange::ChunkSize - std::min(Protocol::FileExchange::ChunkSize, size_t((10 + 5) - 1))), // -11 "path9"
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

	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.reserve(sizes.size());
	const std::minstd_rand::result_type seed = getRandomSeed();
	for (size_t i = 0; i < sizes.size(); ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("path{}", i),
			.data = generateTestFileData(sizes[i], seed + static_cast<std::minstd_rand::result_type>(i)),
		});
	}

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_EverySecondEscapesRoot_EverySecondRejected)
{
	const std::array sizes{
		size_t(100),
		size_t(Protocol::FileExchange::ChunkSize * Protocol::FileExchange::ChunksBetweenAnswers + 1), // the file will be still sending when get rejected
		size_t(300),
		size_t(180), // rejected mid chunk
		size_t(10),
		size_t(Protocol::FileExchange::ChunkSize * Protocol::FileExchange::ChunksBetweenAnswers - std::min(size_t(300 + 180 + 10), Protocol::FileExchange::ChunkSize * Protocol::FileExchange::ChunksBetweenAnswers)), // rejected right at the border of the last chunk before answer
	};

	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.reserve(sizes.size());
	std::vector<TestFileExchangeFile> expectedFilesToReceive;
	expectedFilesToReceive.reserve(sizes.size());
	const std::minstd_rand::result_type seed = getRandomSeed();
	for (size_t i = 0; i < sizes.size(); ++i)
	{
		if ((i + 1) % 2 == 0)
		{
			filesToSend.push_back(TestFileExchangeFile{
				// paths that try to escape the directory should be rejected
				.path = std::format("../path{}", i),
				.data = generateTestFileData(sizes[i], seed + static_cast<std::minstd_rand::result_type>(i)),
			});
		}
		else
		{
			filesToSend.push_back(TestFileExchangeFile{
				.path = std::format("path{}", i),
				.data = generateTestFileData(sizes[i], seed + static_cast<std::minstd_rand::result_type>(i)),
			});
			expectedFilesToReceive.push_back(TestFileExchangeFile{
				.path = filesToSend[i].path,
				.data = filesToSend[i].data,
			});
		}
	}

	runFileExchangeTest(clientStorage, filesToSend, expectedFilesToReceive, expectedFilesToReceive);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveFilesWithWrongPath_AllRejected)
{
	const std::array sizes{
		size_t(100),
		size_t(Protocol::FileExchange::ChunkSize * Protocol::FileExchange::ChunksBetweenAnswers + 1),
		size_t(300),
		size_t(180),
		size_t(10),
		size_t(Protocol::FileExchange::ChunkSize * Protocol::FileExchange::ChunksBetweenAnswers - std::min(size_t(300 + 180 + 10), Protocol::FileExchange::ChunkSize * Protocol::FileExchange::ChunksBetweenAnswers)),
		size_t(100),
	};

	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.reserve(sizes.size());
	const std::minstd_rand::result_type seed = getRandomSeed();
	for (size_t i = 0; i < sizes.size(); ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			// paths that try to escape the directory should be rejected
			.path = std::format("../path{}", i),
			.data = generateTestFileData(sizes[i], seed + static_cast<std::minstd_rand::result_type>(i)),
		});
	}

	runFileExchangeTest(clientStorage, filesToSend, {}, {});
}

TEST(FileSendReceiveUtils, Roundtrip_2000EmptyFiles_SuccessfullyReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	constexpr size_t FilesCount = 2000;
	filesToSend.reserve(FilesCount);
	for (size_t i = 0; i < FilesCount; ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("empty{}", i),
			.data = {},
		});
	}

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_10000EmptyFilesEscapingRoot_AllRejected)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	constexpr size_t FilesCount = 10000;
	filesToSend.reserve(FilesCount);
	for (size_t i = 0; i < FilesCount; ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			// paths that try to escape the directory should be rejected
			.path = std::format("../e{}", i),
			.data = {},
		});
	}

	runFileExchangeTest(clientStorage, filesToSend, {}, {});
}

TEST(FileSendReceiveUtils, Roundtrip_BigAlreadyExistingFiles_AllSkipped)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	constexpr size_t FilesCount = 5;
	filesToSend.reserve(FilesCount);
	const std::minstd_rand::result_type seed = getRandomSeed();
	for (size_t i = 0; i < FilesCount; ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("f{}", i),
			.data = generateTestFileData(4000, seed + static_cast<std::minstd_rand::result_type>(i)),
		});
	}

	runFileExchangeTest(
		clientStorage,
		filesToSend,
		filesToSend, // the existing files should stay
		filesToSend,
		FileExchangeTestInstructions{
			.existingFiles = cloneTestFiles(filesToSend),
			.checkNoFilesWritten = true,
		}
	);
}

TEST(FileSendReceiveUtils, Roundtrip_BigAlreadyExistingButWithHashMismatch_AllReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	constexpr size_t FilesCount = 5;
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.reserve(FilesCount);
	std::vector<TestFileExchangeFile> existingFiles;
	existingFiles.reserve(FilesCount);
	std::vector<std::string> expectedOverriddenFiles;
	expectedOverriddenFiles.reserve(FilesCount);
	const std::minstd_rand::result_type seed = getRandomSeed();
	for (size_t i = 0; i < FilesCount; ++i)
	{
		std::string fileName = std::format("f{}", i);
		filesToSend.push_back(TestFileExchangeFile{
			.path = fileName,
			.data = generateTestFileData(4000, seed + static_cast<std::minstd_rand::result_type>(i) * 2),
		});

		existingFiles.push_back(TestFileExchangeFile{
			.path = fileName,
			.data = generateTestFileData(4000, seed + static_cast<std::minstd_rand::result_type>(i) * 2 + 1),
		});

		expectedOverriddenFiles.push_back(std::move(fileName));
	}

	runFileExchangeTest(
		clientStorage,
		filesToSend,
		filesToSend,
		filesToSend,
		FileExchangeTestInstructions{
			.existingFiles = std::move(existingFiles),
			.expectedOverriddenFiles = std::move(expectedOverriddenFiles),
		}
	);
}

TEST(FileSendReceiveUtils, Roundtrip_BigFilesReceivedCorrupted_AllRejected)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	constexpr size_t FilesCount = 5;
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.reserve(FilesCount);
	std::vector<TestFileExchangeFile> expectedFiles;
	expectedFiles.reserve(FilesCount);
	const std::minstd_rand::result_type seed = getRandomSeed();
	for (size_t i = 0; i < FilesCount; ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("f{}", i),
			.data = generateTestFileData(4000, seed + static_cast<std::minstd_rand::result_type>(i)),
		});

		expectedFiles.push_back(TestFileExchangeFile{
			.path = std::format("f{}", i),
			.data = std::vector<std::byte>(4000, std::byte(0x79)),
		});
	}

	runFileExchangeTest(
		clientStorage,
		filesToSend,
		expectedFiles,
		{},
		FileExchangeTestInstructions{
			.corruptReceivedFilesPattern = std::byte(0x79),
		}
	);
}

TEST(FileSendReceiveUtils, Roundtrip_BigFilesPartiallySentAndThenContinued_OnlyTheRemainderIsReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	constexpr size_t FilesCount = 7;
	filesToSend.reserve(FilesCount);
	const std::minstd_rand::result_type seed = getRandomSeed();
	for (size_t i = 0; i < FilesCount; ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("f{}", i),
			.data = generateTestFileData(8000, seed + static_cast<std::minstd_rand::result_type>(i)),
		});
	}

	std::vector<TestFileExchangeFile> filesToReceiveFirstChunk;
	filesToReceiveFirstChunk.push_back(filesToSend[0].clone());
	filesToReceiveFirstChunk.push_back(filesToSend[1].clone());
	filesToReceiveFirstChunk.push_back(filesToSend[2].clone());
	filesToReceiveFirstChunk.push_back(filesToSend[3].clone());
	filesToReceiveFirstChunk.push_back(filesToSend[4].clone());
	filesToReceiveFirstChunk[4].data.resize(2596);
	std::vector<TestFileExchangeFile> filesToConfirmFirstChunk;
	filesToConfirmFirstChunk.push_back(filesToSend[0].clone());
	filesToConfirmFirstChunk.push_back(filesToSend[1].clone());
	filesToConfirmFirstChunk.push_back(filesToSend[2].clone());
	filesToConfirmFirstChunk.push_back(filesToSend[3].clone());

	AssertHelper::disableAsserts();
	FileExchangeTestResult firstResult = runFileExchangeTest(
		clientStorage,
		filesToSend,
		filesToReceiveFirstChunk,
		filesToConfirmFirstChunk,
		FileExchangeTestInstructions{
			// break right after we received an answer, so we have some files fully received and one file in partiallly confirmed state
			.breakFileSendPipeAfterBytes = Protocol::FileExchange::ChunkSize * Protocol::FileExchange::ChunksBetweenAnswers + 2048,
		}
	);
	AssertHelper::enableAsserts();

	runFileExchangeTest(
		clientStorage,
		filesToSend, // we try to send all files
		filesToSend, // all files should exist on the receiving end after the operation
		filesToSend, // all files wiil be confirmed in the end (skipped, previously partially received, and the rest of received)
		FileExchangeTestInstructions{
			.existingFiles = std::move(firstResult.totalReceivedFiles),
			.expectedOverriddenFiles = std::vector<std::string>({ "f4" }),
		}
	);
}

TEST(FileSendReceiveUtils, Roundtrip_BigFilesPartiallySentAndThenDiscoveredCorrupted_ThePartiallySentFileIsFullyResent)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	constexpr size_t FilesCount = 7;
	filesToSend.reserve(FilesCount);
	const std::minstd_rand::result_type seed = getRandomSeed();
	for (size_t i = 0; i < FilesCount; ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("f{}", i),
			.data = generateTestFileData(8000, seed + static_cast<std::minstd_rand::result_type>(i)),
		});
	}

	std::vector<TestFileExchangeFile> filesToReceiveFirstChunk;
	filesToReceiveFirstChunk.push_back(filesToSend[0].clone());
	filesToReceiveFirstChunk.push_back(filesToSend[1].clone());
	filesToReceiveFirstChunk.push_back(filesToSend[2].clone());
	filesToReceiveFirstChunk.push_back(filesToSend[3].clone());
	filesToReceiveFirstChunk.push_back(filesToSend[4].clone());
	filesToReceiveFirstChunk[4].data.resize(2596);
	std::vector<TestFileExchangeFile> filesToConfirmFirstChunk;
	filesToConfirmFirstChunk.push_back(filesToSend[0].clone());
	filesToConfirmFirstChunk.push_back(filesToSend[1].clone());
	filesToConfirmFirstChunk.push_back(filesToSend[2].clone());
	filesToConfirmFirstChunk.push_back(filesToSend[3].clone());

	std::vector<TestFileExchangeFile> filesToReceiveSecondChunk = filesToReceiveFirstChunk;
	filesToReceiveSecondChunk[4].data[0] = static_cast<std::byte>(static_cast<uint8_t>(filesToReceiveFirstChunk[4].data[0]) + 1);
	filesToReceiveSecondChunk.push_back(filesToSend[5].clone());
	filesToReceiveSecondChunk.push_back(filesToSend[6].clone());
	std::vector<TestFileExchangeFile> filesToConfirmSecondChunk;
	filesToConfirmSecondChunk.push_back(filesToSend[0].clone());
	filesToConfirmSecondChunk.push_back(filesToSend[1].clone());
	filesToConfirmSecondChunk.push_back(filesToSend[2].clone());
	filesToConfirmSecondChunk.push_back(filesToSend[3].clone());
	filesToConfirmSecondChunk.push_back(filesToSend[5].clone());
	filesToConfirmSecondChunk.push_back(filesToSend[6].clone());

	AssertHelper::disableAsserts();
	FileExchangeTestResult firstResult = runFileExchangeTest(
		clientStorage,
		filesToSend,
		filesToReceiveFirstChunk,
		filesToConfirmFirstChunk,
		FileExchangeTestInstructions{
			// break right after we received an answer, so we have some files fully received and one file in partiallly confirmed state
			.breakFileSendPipeAfterBytes = Protocol::FileExchange::ChunkSize * Protocol::FileExchange::ChunksBetweenAnswers + 2048,
		}
	);
	AssertHelper::enableAsserts();

	ASSERT_EQ(firstResult.totalReceivedFiles.size(), size_t(5));
	// corrupt the partially received file on the receiving party
	firstResult.totalReceivedFiles[4].data[0] = static_cast<std::byte>(static_cast<uint8_t>(firstResult.totalReceivedFiles[4].data[0]) + 1);

	FileExchangeTestResult secondResult = runFileExchangeTest(
		clientStorage,
		filesToSend,
		filesToReceiveSecondChunk,
		filesToConfirmSecondChunk,
		FileExchangeTestInstructions{
			.existingFiles = std::move(firstResult.totalReceivedFiles),
		}
	);

	runFileExchangeTest(
		clientStorage,
		filesToSend,
		filesToSend,
		filesToSend,
		FileExchangeTestInstructions{
			.existingFiles = std::move(secondResult.totalReceivedFiles),
			.expectedOverriddenFiles = std::vector<std::string>({ "f4" }),
		}
	);
}
