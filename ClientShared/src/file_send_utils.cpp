// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/file_send_utils.h"

#include <fstream>

#include "common_shared/cryptography/noise/cipher_utils.h"
#include "common_shared/debug/assert.h"
#include "common_shared/network/protocol.h"
#include "common_shared/network/utils.h"
#include "common_shared/serialization/number_serialization.h"

#include "client_shared/file_list_cache.h"

namespace FileSendUtils
{
	/// Files are sent in chunks of 1024 bytes + auth data,
	/// each message is encrypted separately,
	/// rekey is called after each message,
	/// no out-of-order messages allowed.
	/// If the file size does not align to 1024, the next file will be written right after
	/// in the same message if possible. All messages below 1024 bytes are padded with zeroes at the end.
	/// An answer is sent each 32 chunks, or at the end of the transmission.
	struct FileSendingState
	{
		constexpr static size_t ChunkSize = Protocol::FileExchange::ChunkSize;
		constexpr static size_t ChunksBetweenAnswers = Protocol::FileExchange::ChunksBetweenAnswers;
		constexpr static size_t AnswerChunkSize = Protocol::FileExchange::AnswerChunkSize;

#ifdef DEBUG_CHECKS
		constexpr static bool debugPrint = false;
#endif // DEBUG_CHECKS

		enum class DebugState
		{
			StartChunk,
			FileSize,
			FilePathSize,
			FilePath,
			FileContent,
			FileContentSkipped,
			EndFile,
			NewFile,
			EndTransmission,
			EndChunk,
			Answer,
			AnswerExtraChunk,
		};

		void debugPrintState([[maybe_unused]] DebugState state)
		{
#ifdef DEBUG_CHECKS
			if constexpr (debugPrint)
			{
				switch (state)
				{
				case DebugState::StartChunk:
					Debug::Log::printDebug("Send:  /---------------\\\nSend: / #{:03}            \\", chunksSent);
					break;
				case DebugState::FileSize:
					Debug::Log::printDebug("Send: |    file size     |");
					break;
				case DebugState::FilePathSize:
					Debug::Log::printDebug("Send: |  file path size  |");
					break;
				case DebugState::FilePath:
					Debug::Log::printDebug("Send: |    file path     |");
					break;
				case DebugState::FileContent:
					Debug::Log::printDebug("Send: |   file content   |");
					break;
				case DebugState::FileContentSkipped:
					Debug::Log::printDebug("Send: |file content(skip)|");
					break;
				case DebugState::EndFile:
					Debug::Log::printDebug("Send: | --- end file --- |");
					break;
				case DebugState::NewFile:
					Debug::Log::printDebug("Send: > --- new file --- <");
					break;
				case DebugState::EndTransmission:
					Debug::Log::printDebug("Send: | !! end stream !! |");
					break;
				case DebugState::EndChunk:
					Debug::Log::printDebug("Send: \\                 /\nSend:  \\---------------/");
					break;
				case DebugState::Answer:
					Debug::Log::printDebug("Send: [[   read answer  ]]");
					break;
				case DebugState::AnswerExtraChunk:
					Debug::Log::printDebug("Send: [[ read answer ++ ]]");
					break;
				default:
					break;
				}
			}
#endif // DEBUG_CHECKS
		}

#ifdef WITH_TESTS
		Mocks mocks;
#endif
		Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, ChunkSize + Cryptography::CipherAuthDataSize> buffer;
		std::string filePath;
		size_t bytesFilledInChunk = 0;
		size_t chunksSent = 0;
		size_t fileMetadataBytes = 0; // 8 bytes of size + 2 bytes of path + name
		size_t fileMetadataWritten = 0;
		size_t fileSizeBytes = 0;
		uint16_t filePathSize = 0;
		size_t bytesReadFromFile = 0;
		size_t fileIndex = 0;
		std::vector<std::filesystem::path> filesAwaitingConfirmation;
		FileListCache acceptedFilesCache{ "sent_cache.txt" };

		[[nodiscard]] bool isBufferEmpty() const noexcept
		{
			return bytesFilledInChunk == 0;
		}

		[[nodiscard]] bool isBufferFull() const noexcept
		{
			return bytesFilledInChunk == ChunkSize;
		}

		[[nodiscard]] bool hasFileFinished() const noexcept
		{
			return fileMetadataWritten == fileMetadataBytes && bytesReadFromFile == fileSizeBytes;
		}

		[[nodiscard]] bool haveUnconfirmedFiles() const noexcept
		{
			return !filesAwaitingConfirmation.empty();
		}

		void getAllFiles(const std::filesystem::path& rootPath, std::vector<std::filesystem::path>& outPaths)
		{
#ifdef WITH_TESTS
			if (mocks.getAllFiles)
			{
				return mocks.getAllFiles(outPaths);
			}
#endif

			for (auto dirEntry : std::filesystem::recursive_directory_iterator(rootPath))
			{
				if (!std::filesystem::is_directory(dirEntry))
				{
					outPaths.push_back(dirEntry.path());
				}
			}
		}

		void openFile(std::ifstream& stream, const std::filesystem::path& path)
		{
#ifdef WITH_TESTS
			if (mocks.openFile)
			{
				mocks.openFile(stream, path);
				return;
			}
#endif
			stream.open(path, std::ios::binary | std::ios::in);
		}

		size_t getFileLength(std::ifstream& file) const
		{
#ifdef WITH_TESTS
			if (mocks.getFileLength)
			{
				return mocks.getFileLength(file);
			}
#endif

			file.seekg(0, std::ios::end);
			const size_t size = static_cast<size_t>(file.tellg());
			file.seekg(0, std::ios::beg);
			return size;
		}

		bool isFileOpen(std::ifstream& stream) const
		{
#ifdef WITH_TESTS
			if (mocks.isFileOpen)
			{
				return mocks.isFileOpen(stream);
			}
#endif

			return stream.is_open();
		}

		void readFileStreamIntoSpan(std::ifstream& stream, std::span<std::byte> bufferSpan)
		{
#ifdef WITH_TESTS
			if (mocks.readFileStreamIntoSpan)
			{
				mocks.readFileStreamIntoSpan(stream, bufferSpan);
				return;
			}
#endif

			stream.read(reinterpret_cast<char*>(bufferSpan.data()), bufferSpan.size());
		}

		std::optional<std::string> sendBuffer(Network::RawSocket socket, std::span<std::byte> bufferSpan, size_t bytesFilledInBuffer, Noise::CipherStateSending& sendingCipherstate)
		{
#ifdef WITH_TESTS
			if (mocks.sendBuffer)
			{
				return mocks.sendBuffer(socket, bufferSpan, bytesFilledInBuffer, sendingCipherstate);
			}
#endif

			return Network::sendEncrypted(socket, bufferSpan, bytesFilledInBuffer, sendingCipherstate);
		}

		std::optional<std::string> recvAnswerBuffer(Network::RawSocket socket, std::span<std::byte> bufferSpan, size_t& bytesFilledInBuffer, Noise::CipherStateReceiving& receivingCipherstate)
		{
#ifdef WITH_TESTS
			if (mocks.recvAnswerBuffer)
			{
				return mocks.recvAnswerBuffer(socket, bufferSpan, bytesFilledInBuffer, receivingCipherstate);
			}
#endif

			return Network::recvEncrypted(socket, bufferSpan, bytesFilledInBuffer, receivingCipherstate);
		}

		[[nodiscard]] size_t partiallyWriteDataToChunk(std::span<const std::byte> data, size_t alreadyWrittenBytes) noexcept
		{
			assertFatalRelease(bytesFilledInChunk < ChunkSize && alreadyWrittenBytes < data.size(), "logical error, precondition failed, some of the sizes in partiallyWriteDataToChunk don't make sense");
			const size_t bytesToCopy = std::min(data.size() - alreadyWrittenBytes, ChunkSize - bytesFilledInChunk);
			std::copy(
				data.begin() + alreadyWrittenBytes,
				data.begin() + (alreadyWrittenBytes + bytesToCopy),
				buffer.raw.begin() + bytesFilledInChunk
			);
			bytesFilledInChunk += bytesToCopy;
			return bytesToCopy;
		}

		void newFile(const std::filesystem::path& path, size_t size) noexcept
		{
			filePath = path.generic_string();
			fileSizeBytes = size;
			bytesReadFromFile = 0;
			fileMetadataWritten = 0;
			filePathSize = static_cast<uint16_t>(filePath.size());
			fileMetadataBytes = 8 + 2 + filePathSize;
			filesAwaitingConfirmation.push_back(path);
			++fileIndex;
			debugPrintState(DebugState::NewFile);
		}

		void readFileIntoBuffer(std::ifstream& file) noexcept
		{
			if (fileMetadataWritten < fileMetadataBytes)
			{
				if (fileMetadataWritten < 8)
				{
					debugPrintState(DebugState::FileSize);
					std::array<std::byte, 8> data;
					Serialization::writeUint64(data, fileSizeBytes);
					fileMetadataWritten += partiallyWriteDataToChunk(data, fileMetadataWritten);
					if (isBufferFull())
					{
						return;
					}
				}

				if (fileMetadataWritten < 8 + 2)
				{
					debugPrintState(DebugState::FilePathSize);
					std::array<std::byte, 2> data;
					Serialization::writeUint16(data[0], data[1], filePathSize);
					fileMetadataWritten += partiallyWriteDataToChunk(data, fileMetadataWritten - 8);
					if (isBufferFull())
					{
						return;
					}
				}

				debugPrintState(DebugState::FilePath);
				fileMetadataWritten += partiallyWriteDataToChunk(std::span<std::byte>(reinterpret_cast<std::byte*>(filePath.data()), filePathSize), fileMetadataWritten - (8 + 2));
				if (isBufferFull())
				{
					return;
				}
			}

			debugPrintState(DebugState::FileContent);
			const size_t bytesToRead = std::min(fileSizeBytes - bytesReadFromFile, ChunkSize - bytesFilledInChunk);
			readFileStreamIntoSpan(file, std::span(buffer.raw.data() + bytesFilledInChunk, bytesToRead));
			bytesReadFromFile += bytesToRead;
			bytesFilledInChunk += bytesToRead;
			assertFatalRelease(bytesReadFromFile <= fileSizeBytes, "File read size bigger than file size, this should never happen");
		}

		[[nodiscard]] bool sendChunk(Network::RawSocket socket, Noise::CipherStateSending& sendingCipherstate) noexcept
		{
			if (bytesFilledInChunk != ChunkSize) [[unlikely]]
			{
				reportDebugError("We should never try to send partially filled chunks, should use fillRemainderWithZeroes");
				return false;
			}

			auto sendResult = sendBuffer(socket, buffer, bytesFilledInChunk, sendingCipherstate);
			if (sendResult.has_value()) [[unlikely]]
			{
				reportDebugError("Could not send file part: {}", *sendResult);
				return false;
			}

			Noise::Utils::rekey(sendingCipherstate);

			++chunksSent;
			bytesFilledInChunk = 0;
			std::fill(buffer.raw.begin(), buffer.raw.end(), std::byte(0x00));

			return true;
		}

		[[nodiscard]] bool shouldReadAnswer() const noexcept
		{
			return chunksSent != 0 && chunksSent % ChunksBetweenAnswers == 0;
		}

		void fillRemainderWithZeroes() noexcept
		{
			std::fill(buffer.raw.begin() + bytesFilledInChunk, buffer.raw.end(), std::byte(0x00));
			bytesFilledInChunk = ChunkSize;
		}

		void recordAndClearConfirmations(const std::vector<size_t>& errorIndexes) noexcept
		{
			const bool shouldRecordLast = hasFileFinished();
			const size_t count = filesAwaitingConfirmation.size() + (shouldRecordLast ? 0 : -1);
			size_t indexPos = 0;
			const size_t indexesSize = errorIndexes.size();
			for (size_t i = 0; i < count; ++i)
			{
				if (indexPos < indexesSize && errorIndexes[indexPos] == i)
				{
					++indexPos;
					continue;
				}

				acceptedFilesCache.recordFile(filesAwaitingConfirmation[i]);
			}

			if (shouldRecordLast)
			{
				filesAwaitingConfirmation.clear();
			}
			else if (!filesAwaitingConfirmation.empty())
			{
				filesAwaitingConfirmation.erase(filesAwaitingConfirmation.begin(), filesAwaitingConfirmation.begin() + (filesAwaitingConfirmation.size() - 1));
			}
		}

		[[nodiscard]] bool readAnswer(Network::RawSocket socket, Noise::CipherStateReceiving& receivingCipherstate, [[maybe_unused]] bool isMidSendingEndState = false) noexcept
		{
			// read the big comment in Protocol::FileExchange for the explanation

			constexpr size_t BitsetOffset = 2;

			debugPrintState(DebugState::Answer);

			if (filesAwaitingConfirmation.empty()) [[unlikely]]
			{
				reportDebugError("Reading confirmation when have no files needing to confirm");
				return false;
			}

			const bool hasFileInProgress = !hasFileFinished();

			Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, AnswerChunkSize + Cryptography::CipherAuthDataSize> receivingBuffer;

			size_t posInChunk = 0;
			auto readChunk = [this, socket, &receivingBuffer, &receivingCipherstate, &posInChunk] {
				size_t bytesReceived = 0;
				if (auto result = recvAnswerBuffer(socket, receivingBuffer, bytesReceived, receivingCipherstate); result.has_value()) [[unlikely]]
				{
					reportDebugError("Could not recv answer chunk: {}", *result);
					return false;
				}

				if (bytesReceived != AnswerChunkSize) [[unlikely]]
				{
					reportDebugError("Unexpected answer chunk size {}", bytesReceived);
					return false;
				}

				Noise::Utils::rekey(receivingCipherstate);
				posInChunk = 0;

				return true;
			};

			if (!readChunk())
			{
				return false;
			}

			const uint16_t statusesToRead = Serialization::readUint16(receivingBuffer.raw[0], receivingBuffer.raw[1]);
			posInChunk += 2;

			// make sure it won't compile if we configure the file transfer logic in a way that is not supported
			static_assert(AnswerChunkSize >= 3, "This code doesn't expect answer chunk size less than 3 bytes");
			static_assert(ChunksBetweenAnswers * ChunkSize > 2 + 8, "We can't have less data sent between answers than the size of the static metadata + 1");

			debugAssert(statusesToRead == filesAwaitingConfirmation.size() + (isMidSendingEndState ? 1 : 0), "Received unexpected number of file statuses {} == {}", statusesToRead, filesAwaitingConfirmation.size() + (isMidSendingEndState ? 1 : 0));

			const size_t bytesInBitset = (statusesToRead + 7) / 8;

			const size_t bitsetChunks = (BitsetOffset + bytesInBitset + AnswerChunkSize - 1) / AnswerChunkSize;

			if (bitsetChunks == 1) [[likely]]
			{
				size_t popcount = 0;
				for (size_t i = 0; i < bytesInBitset; ++i)
				{
					popcount += std::popcount(static_cast<uint8_t>(receivingBuffer.raw[BitsetOffset + i]));
				}

				// this is the most likely situation, that we have only a few files that got confirmed
				if (popcount == 0) [[likely]]
				{
					recordAndClearConfirmations({});
					return true;
				}
			}

			// process error cases, or multi-block bistet
			size_t errorStartIndex = 0;
			size_t bytePosInBitset = 0;
			std::vector<size_t> errorFileIndexes;
			errorFileIndexes.reserve(statusesToRead);
			for (size_t chunkIdx = 0; chunkIdx < bitsetChunks; ++chunkIdx)
			{
				if (posInChunk == AnswerChunkSize)
				{
					debugPrintState(DebugState::AnswerExtraChunk);
					if (!readChunk())
					{
						return false;
					}
				}

				for (; bytePosInBitset < bytesInBitset && posInChunk < AnswerChunkSize; ++bytePosInBitset, ++posInChunk)
				{
					const uint8_t byte = static_cast<uint8_t>(receivingBuffer.raw[posInChunk]);

					for (size_t j = 0; j < 8; ++j)
					{
						if ((byte & (static_cast<uint8_t>(1) << (7 - j))) != 0)
						{
							errorFileIndexes.push_back(errorStartIndex + j);
						}
					}
					errorStartIndex += 8;
				}
			}

			assertFatalRelease(posInChunk == (BitsetOffset + bytesInBitset) % AnswerChunkSize || posInChunk == AnswerChunkSize, "Unexpected chunk pos {} == {}", posInChunk, (BitsetOffset + bytesInBitset) % AnswerChunkSize);

			const size_t errorsArraySize = errorFileIndexes.size();
			const size_t chunksToReseive = (posInChunk + errorsArraySize + AnswerChunkSize - 1) / AnswerChunkSize;
			assertFatalRelease(chunksToReseive != 0, "Can't have zero chunks to send as an answer");

			errorStartIndex = 0;
			for (size_t chunkIdx = 0; chunkIdx < chunksToReseive; ++chunkIdx)
			{
				for (; errorStartIndex < errorFileIndexes.size() && posInChunk < AnswerChunkSize; ++errorStartIndex, ++posInChunk)
				{
					const size_t fileIdx = errorFileIndexes[errorStartIndex];
					switch (static_cast<uint8_t>(receivingBuffer.raw[posInChunk]))
					{
					case static_cast<uint8_t>(Protocol::FileExchange::FileReceiveStatus::BadFilePath):
						// ToDo: log an error
						break;
					default:
						reportDebugError("Unknown file error status {}", static_cast<uint8_t>(receivingBuffer.raw[posInChunk]));
						return false;
					}

					if (hasFileInProgress && fileIdx + 1 == filesAwaitingConfirmation.size())
					{
						// currrent file was rejected, stop reading it
						bytesReadFromFile = fileSizeBytes;
						fileMetadataWritten = fileMetadataBytes;
					}
					else if (fileIdx >= filesAwaitingConfirmation.size()) [[unlikely]]
					{
						reportDebugError("File confirmation index out of bounds {} of {}", fileIdx, filesAwaitingConfirmation.size());
						return false;
					}
				}

				if (chunkIdx + 1 < chunksToReseive)
				{
					debugPrintState(DebugState::AnswerExtraChunk);
					debugAssert(posInChunk == AnswerChunkSize, "We finished reading not last chunk too early: {}", posInChunk);

					if (!readChunk())
					{
						return false;
					}
				}
			}

			recordAndClearConfirmations(errorFileIndexes);
			return true;
		}
	};

	std::vector<std::filesystem::path> sendDirectory(const std::filesystem::path& directoryPath, const std::filesystem::path& commonRoot, Network::RawSocket socket, ClientStorage& storage, Noise::CipherStateSending& sendingCipherstate, Noise::CipherStateReceiving& receivingCipherState, [[maybe_unused]] Mocks mocks) noexcept
	{
		FileSendingState sendingState;

#ifdef WITH_TESTS
		sendingState.mocks = std::move(mocks);
#endif

		std::vector<std::filesystem::path> files;

		try
		{
			sendingState.getAllFiles(directoryPath, files);

			sendingState.debugPrintState(FileSendingState::DebugState::StartChunk);

			for (const auto& dirEntry : files)
			{
				bool hasFileBeenTransferred = false;
				storage.read([&hasFileBeenTransferred, &dirEntry, &commonRoot](const ClientStorageData& storageData) {
#if defined(_WIN32) || defined(_WIN64)
					if (storageData.sentFiles.contains(dirEntry.lexically_relative(commonRoot).string()))
#else
					if (storageData.sentFiles.contains(dirEntry.lexically_relative(commonRoot)))
#endif

					{
						hasFileBeenTransferred = true;
					}
				});

				if (hasFileBeenTransferred)
				{
					continue;
				}

				std::ifstream file;
				sendingState.openFile(file, dirEntry);

				if (!sendingState.isFileOpen(file)) [[unlikely]]
				{
					reportDebugError("Could not open file for reading: {}", dirEntry.string());
					return sendingState.acceptedFilesCache.consumeAllFiles();
				}

				sendingState.newFile(dirEntry.lexically_relative(commonRoot), sendingState.getFileLength(file));

				while (true)
				{
					sendingState.readFileIntoBuffer(file);

					if (sendingState.isBufferFull())
					{
						sendingState.debugPrintState(FileSendingState::DebugState::EndChunk);

						if (!sendingState.sendChunk(socket, sendingCipherstate))
						{
							return sendingState.acceptedFilesCache.consumeAllFiles();
						}

						if (sendingState.shouldReadAnswer())
						{
							if (!sendingState.readAnswer(socket, receivingCipherState))
							{
								return sendingState.acceptedFilesCache.consumeAllFiles();
							}
						}

						sendingState.debugPrintState(FileSendingState::DebugState::StartChunk);
					}

					if (sendingState.hasFileFinished())
					{
						sendingState.debugPrintState(FileSendingState::DebugState::EndFile);
						break;
					}
				}
			}

			// append 10 zero bytes (empty file with empty path) to signal about the transmission end
			{
				sendingState.debugPrintState(FileSendingState::DebugState::FileSize);
				sendingState.debugPrintState(FileSendingState::DebugState::FilePathSize);
				sendingState.debugPrintState(FileSendingState::DebugState::EndTransmission);
				size_t endingBytesWritten = 0;
				std::array<std::byte, 10> endingBytes = {};
				while (endingBytesWritten < endingBytes.size())
				{
					endingBytesWritten += sendingState.partiallyWriteDataToChunk(endingBytes, endingBytesWritten);
					if (sendingState.isBufferFull())
					{
						if (!sendingState.sendChunk(socket, sendingCipherstate))
						{
							return sendingState.acceptedFilesCache.consumeAllFiles();
						}

						if (sendingState.shouldReadAnswer())
						{
							if (!sendingState.readAnswer(socket, receivingCipherState, endingBytesWritten < endingBytes.size()))
							{
								return sendingState.acceptedFilesCache.consumeAllFiles();
							}
						}
					}
				}
			}

			// send the remainder of the buffer padded with zeroes
			if (!sendingState.isBufferEmpty())
			{
				if (!sendingState.isBufferFull())
				{
					sendingState.fillRemainderWithZeroes();
				}

				if (!sendingState.sendChunk(socket, sendingCipherstate))
				{
					return sendingState.acceptedFilesCache.consumeAllFiles();
				}

				sendingState.debugPrintState(FileSendingState::DebugState::EndChunk);
			}

			if (sendingState.haveUnconfirmedFiles())
			{
				if (!sendingState.readAnswer(socket, receivingCipherState))
				{
					return sendingState.acceptedFilesCache.consumeAllFiles();
				}
			}

			assertRelease(sendingState.filesAwaitingConfirmation.empty(), "Did not expect to have non-empty array of files awaiting confirmation at the end of successful transmission {}", sendingState.filesAwaitingConfirmation.size());
		}
		catch (std::exception& e)
		{
			reportDebugError("An exception caught when sending files: {}", e.what());
			return sendingState.acceptedFilesCache.consumeAllFiles();
		}
		catch (...)
		{
			reportDebugError("An exception caught when sending files");
			return sendingState.acceptedFilesCache.consumeAllFiles();
		}

		return sendingState.acceptedFilesCache.consumeAllFiles();
	}
} // namespace FileSendUtils
