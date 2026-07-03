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

static std::vector<std::byte> generateTestFileData(size_t size)
{
	std::minstd_rand random;
	random.seed(static_cast<std::minstd_rand::result_type>(time(nullptr)));

	std::vector<std::byte> result;
	result.resize(size);
	for (size_t i = 0; i < size; ++i)
	{
		result[i] = std::byte(random() % 256);
	}
	return result;
}

struct FileExchangeTestInstructions
{
	size_t breakSendPipeAfterBytes = std::numeric_limits<size_t>::max();
	std::vector<TestFileExchangeFile> existingFiles = {};
	std::optional<std::byte> corruptReceivedFilesPattern = {};
	bool checkNoFilesWritten = false;
};

struct FileExchangeTestResult
{
	std::vector<TestFileExchangeFile> totalReceivedFiles = {};
};

static FileExchangeTestResult runFileExchangeTest(ClientStorage& clientStorage, const std::vector<TestFileExchangeFile>& filesToSend, const std::vector<TestFileExchangeFile>& expectedFilesToReceive, const std::vector<TestFileExchangeFile>& expectedFilesToConfirm, const FileExchangeTestInstructions& instructions = {})
{
	Cryptography::CipherKey cipherKeyFromSenderToReceiver;
	Cryptography::fillWithRandomBytes(cipherKeyFromSenderToReceiver);
	Cryptography::CipherKey cipherKeyFromReceiverToSender;
	Cryptography::fillWithRandomBytes(cipherKeyFromReceiverToSender);

	TestMessagePipe<Protocol::FileExchange::ChunkSize + Cryptography::CipherAuthDataSize> fileMessages;
	TestMessagePipe<Protocol::FileExchange::AnswerChunkSize + Cryptography::CipherAuthDataSize> answerMessages;

	std::vector<std::filesystem::path> confirmedFiles;

	auto sendingThread = std::thread([&filesToSend, &confirmedFiles, &fileMessages, &answerMessages, &cipherKeyFromSenderToReceiver, &cipherKeyFromReceiverToSender, &clientStorage, &instructions]() {
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
			.openFile = [&filesToSend, &fileToWriteIdx, &fileCursor](std::ifstream&, const std::filesystem::path& path) {
				++fileToWriteIdx;
				fileCursor = 0;
				EXPECT_EQ(filesToSend[fileToWriteIdx].path, path);
			},
			.getFileLength = [&filesToSend, &fileToWriteIdx](std::ifstream&) -> uint64_t {
				return static_cast<uint64_t>(filesToSend[fileToWriteIdx].data.size());
			},
			.isFileOpen = [](std::ifstream&) -> bool {
				return true;
			},
			.calculateFileHash = [&filesToSend, &fileToWriteIdx](std::ifstream&, size_t, Cryptography::HashResult& result) -> int {
				Cryptography::hashSpan(filesToSend[fileToWriteIdx].data, result);
				return 0;
			},
			.readFileStreamIntoSpan = [&filesToSend, &fileToWriteIdx, &fileCursor](std::ifstream&, std::span<std::byte> buffer) {
				std::copy(filesToSend[fileToWriteIdx].data.data() + fileCursor, filesToSend[fileToWriteIdx].data.data() + fileCursor + buffer.size(), buffer.data());
				fileCursor += buffer.size();
			},
			.sendBuffer = [&fileMessages, &bytesWritten, &instructions](Network::RawSocket, std::span<std::byte> buffer, size_t bytesToWrite, Noise::CipherStateSending& sendingState) -> std::optional<std::string> {
				EXPECT_EQ(buffer.size(), Protocol::FileExchange::ChunkSize + Cryptography::CipherAuthDataSize);
				EXPECT_EQ(bytesToWrite, Protocol::FileExchange::ChunkSize);
				EXPECT_EQ(Noise::Utils::encryptTransportMessageInplace(sendingState, buffer), Cryptography::EncryptResult::Success);
				fileMessages.push(buffer);

				bytesWritten += bytesToWrite;
				if (bytesWritten > instructions.breakSendPipeAfterBytes)
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

		confirmedFiles = FileSendUtils::sendDirectory("", "", 0, clientStorage, cipherStateSending, cipherStateReceiving, sendMocks);

		EXPECT_TRUE(getAllFilesCalled);
	});

	std::vector<TestFileExchangeFile> receivedFiles = cloneTestFiles(instructions.existingFiles);
	receivedFiles.reserve(filesToSend.size());

	FileReceiveUtils::Mocks receiveMocks{
		.recvBuffer = [&fileMessages](Network::RawSocket, std::span<std::byte> buffer, size_t& bytesReceived, Noise::CipherStateReceiving& receivingState) -> std::optional<std::string> {
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

			bytesReceived = BytesToReturn;
			return std::nullopt;
		},
		.isFileExists = [&receivedFiles](const std::filesystem::path& path) {
			return std::find_if(receivedFiles.begin(), receivedFiles.end(), [&path](const TestFileExchangeFile& file) {
					   return file.path == path;
				   })
				!= receivedFiles.end();
		},
		.openFile = [&receivedFiles, &instructions](std::ofstream&, const std::filesystem::path& path) {
			receivedFiles.push_back(TestFileExchangeFile{
				.path = path,
				.data = {},
			});
			ASSERT_FALSE(instructions.checkNoFilesWritten);
		},
		.isFileOpen = [](std::ofstream&) -> bool {
			return true;
		},
		.calculateFileHash = [&receivedFiles](const std::filesystem::path& path, Cryptography::HashResult& hashResult) -> int {
			auto it = std::find_if(receivedFiles.begin(), receivedFiles.end(), [&path](const TestFileExchangeFile& file) {
				return file.path == path;
			});

			if (it == receivedFiles.end())
			{
				return -1;
			}

			Cryptography::hashSpan(it->data, hashResult);
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

	EXPECT_EQ(receivedFiles.size(), expectedFilesToReceive.size());
	EXPECT_EQ(receivedFiles, expectedFilesToReceive);

	EXPECT_EQ(expectedFilesToConfirm.size(), confirmedFiles.size());
	for (const auto& expectedFile : expectedFilesToConfirm)
	{
		EXPECT_NE(std::find(confirmedFiles.begin(), confirmedFiles.end(), expectedFile.path), confirmedFiles.end());
	}

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
		.openFile = [](std::ifstream&, const std::filesystem::path&) {
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
	EXPECT_EQ(FileSendUtils::sendDirectory("", "", 0, storage, cipherStateSending, cipherStateReceiving, sendMocks), std::vector<std::filesystem::path>{});

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
		.openFile = [](std::ofstream&, const std::filesystem::path&) {
			FAIL();
		},
		.isFileOpen = [](std::ofstream&) -> bool {
			return false;
		},
		.calculateFileHash = [](const std::filesystem::path&, Cryptography::HashResult& outHash) -> int {
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
		.data = generateTestFileData(4),
	});

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveOneSmallFile_SuccessfullyReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.push_back(TestFileExchangeFile{
		.path = "small.txt",
		.data = generateTestFileData(500),
	});

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveOneMediumFile_SuccessfullyReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.push_back(TestFileExchangeFile{
		.path = "med.txt",
		.data = generateTestFileData(3000),
	});

	runFileExchangeTest(clientStorage, filesToSend, filesToSend, filesToSend);
}

TEST(FileSendReceiveUtils, Roundtrip_SendAndReceiveOneBigFile_SuccessfullyReceived)
{
	ClientStorage clientStorage = ClientStorage::testCreateEmpty();
	std::vector<TestFileExchangeFile> filesToSend;
	filesToSend.push_back(TestFileExchangeFile{
		.path = "big.txt",
		.data = generateTestFileData(200000),
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
	for (size_t i = 0; i < sizes.size(); ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("path{}", i),
			.data = generateTestFileData(sizes[i]),
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
	for (size_t i = 0; i < sizes.size(); ++i)
	{
		if ((i + 1) % 2 == 0)
		{
			filesToSend.push_back(TestFileExchangeFile{
				// paths that try to escape the directory should be rejected
				.path = std::format("../path{}", i),
				.data = generateTestFileData(sizes[i]),
			});
		}
		else
		{
			filesToSend.push_back(TestFileExchangeFile{
				.path = std::format("path{}", i),
				.data = generateTestFileData(sizes[i]),
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
	for (size_t i = 0; i < sizes.size(); ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			// paths that try to escape the directory should be rejected
			.path = std::format("../path{}", i),
			.data = generateTestFileData(sizes[i]),
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
	for (size_t i = 0; i < FilesCount; ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("f{}", i),
			.data = generateTestFileData(4000),
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
	for (size_t i = 0; i < FilesCount; ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("f{}", i),
			.data = generateTestFileData(4000),
		});

		existingFiles.push_back(TestFileExchangeFile{
			.path = std::format("f{}", i),
			.data = generateTestFileData(4000), // different hash
		});
	}

	runFileExchangeTest(
		clientStorage,
		filesToSend,
		filesToSend,
		filesToSend,
		FileExchangeTestInstructions{
			.existingFiles = std::move(existingFiles),
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
	for (size_t i = 0; i < FilesCount; ++i)
	{
		filesToSend.push_back(TestFileExchangeFile{
			.path = std::format("f{}", i),
			.data = generateTestFileData(4000),
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
