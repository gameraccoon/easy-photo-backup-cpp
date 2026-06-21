// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/file_receive_utils.h"

#include <fstream>
#include <limits>

#include "common_shared/cryptography/noise/cipher_utils.h"
#include "common_shared/debug/assert.h"
#include "common_shared/files/file_utils.h"
#include "common_shared/network/protocol.h"
#include "common_shared/network/utils.h"
#include "common_shared/serialization/number_serialization.h"

namespace FileReceiveUtils
{
	/// Files are sent in chunks of 1024 bytes + auth data,
	/// each message is encrypted separately,
	/// rekey is called after each message,
	/// no out-of-order messages allowed.
	/// If the file size does not align to 1024, the next file will be written right after
	/// in the same message if possible. All messages below 1024 bytes are padded with zeroes at the end.
	/// An answer is sent each 32 chunks, or at the end of the transmission.
	struct FileReceivingState
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
					Debug::Log::printDebug("Receive:\t\t\t  /---------------\\\nReceive:\t\t\t / #{:03}            \\", chunksReceived - 1);
					break;
				case DebugState::FileSize:
					Debug::Log::printDebug("Receive:\t\t\t |    file size     |");
					break;
				case DebugState::FilePathSize:
					Debug::Log::printDebug("Receive:\t\t\t |  file path size  |");
					break;
				case DebugState::FilePath:
					Debug::Log::printDebug("Receive:\t\t\t |    file path     |");
					break;
				case DebugState::FileContent:
					Debug::Log::printDebug("Receive:\t\t\t |   file content   |");
					break;
				case DebugState::FileContentSkipped:
					Debug::Log::printDebug("Receive:\t\t\t |file content(skip)|");
					break;
				case DebugState::EndFile:
					Debug::Log::printDebug("Receive:\t\t\t | --- end file --- |");
					break;
				case DebugState::NewFile:
					Debug::Log::printDebug("Receive:\t\t\t > --- new file --- <");
					break;
				case DebugState::EndTransmission:
					Debug::Log::printDebug("Receive:\t\t\t | !! end stream !! |");
					break;
				case DebugState::EndChunk:
					Debug::Log::printDebug("Receive:\t\t\t \\                 /\nReceive:\t\t\t  \\---------------/");
					break;
				case DebugState::Answer:
					Debug::Log::printDebug("Receive:\t\t\t [[   send answer  ]]");
					break;
				case DebugState::AnswerExtraChunk:
					Debug::Log::printDebug("Receive:\t\t\t [[ send answer ++ ]]");
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
		std::ofstream file;
		std::filesystem::path rootPath;
		std::string filePath;
		size_t bytesReadInChunk = ChunkSize;
		size_t chunksReceived = 0;
		size_t fileMetadataRead = 0;
		size_t fileSizeBytes = 0;
		uint16_t filePathSize = 0;
		size_t bytesWrittenToFile = 0;
		size_t currentFileIndex = std::numeric_limits<size_t>::max();
		std::vector<Protocol::FileExchange::FileReceiveStatus> lastFileStatuses;

		[[nodiscard]] bool isBufferFullyRead() const noexcept
		{
			return bytesReadInChunk == ChunkSize;
		}

		[[nodiscard]] bool hasFileFinished() const noexcept
		{
			return fileMetadataRead == static_cast<size_t>(2 + 8) + filePathSize && bytesWrittenToFile == fileSizeBytes;
		}

		[[nodiscard]] bool haveUnconfirmedFiles() const noexcept
		{
			return lastFileStatuses.size() > 1 || (lastFileStatuses.size() == 1 && !hasFileFinished());
		}

		[[nodiscard]] bool currentFileHasNoErrors() const noexcept
		{
			debugAssert(!lastFileStatuses.empty(), "Last file statuses not expected to be empty");
			return !lastFileStatuses.empty() && lastFileStatuses.back() == Protocol::FileExchange::FileReceiveStatus::Success;
		}

		std::optional<std::string> recvBuffer(Network::RawSocket socket, std::span<std::byte> bufferSpan, size_t& bytesReceived, Noise::CipherStateReceiving& receivingCipherstate)
		{
#ifdef WITH_TESTS
			if (mocks.recvBuffer)
			{
				return mocks.recvBuffer(socket, bufferSpan, bytesReceived, receivingCipherstate);
			}
#endif

			return Network::recvEncrypted(socket, bufferSpan, bytesReceived, receivingCipherstate);
		}

		void openFile(std::ofstream& stream, const std::filesystem::path& path)
		{
#ifdef WITH_TESTS
			if (mocks.openFile)
			{
				mocks.openFile(stream, path);
				return;
			}
#endif

			std::filesystem::path parentDirectory = path.parent_path();
			if (!std::filesystem::exists(parentDirectory))
			{
				std::filesystem::create_directory(parentDirectory);
			}

			stream.open(path, std::ios::binary | std::ios::out);
		}

		bool isFileOpen(std::ofstream& stream) const
		{
#ifdef WITH_TESTS
			if (mocks.isFileOpen)
			{
				return mocks.isFileOpen(stream);
			}
#endif

			return stream.is_open();
		}

		void writeSpanIntoStream(std::ofstream& stream, std::span<const std::byte> bufferSpan)
		{
#ifdef WITH_TESTS
			if (mocks.openFile)
			{
				mocks.writeSpanIntoStream(stream, bufferSpan);
				return;
			}
#endif

			stream.write(reinterpret_cast<const char*>(bufferSpan.data()), bufferSpan.size());
		}

		std::optional<std::string> sendAnswerBuffer(Network::RawSocket socket, std::span<std::byte> bufferToSend, size_t bytesToSend, Noise::CipherStateSending& sendingCipherstate)
		{
#ifdef WITH_TESTS
			if (mocks.sendAnswerBuffer)
			{
				return mocks.sendAnswerBuffer(socket, bufferToSend, bytesToSend, sendingCipherstate);
			}
#endif

			return Network::sendEncrypted(socket, bufferToSend, bytesToSend, sendingCipherstate);
		}

		[[nodiscard]] size_t partiallyReadDataFromChunk(std::span<std::byte> data, size_t alreadyReadBytes) noexcept
		{
			assertFatalRelease(bytesReadInChunk < ChunkSize && alreadyReadBytes < data.size(), "logical error, precondition failed, some of the sizes in partiallyReadDataFromChunk don't make sense");
			const size_t bytesToCopy = std::min(data.size() - alreadyReadBytes, ChunkSize - bytesReadInChunk);
			std::copy(
				buffer.raw.begin() + bytesReadInChunk,
				buffer.raw.begin() + bytesReadInChunk + bytesToCopy,
				data.begin() + alreadyReadBytes
			);
			bytesReadInChunk += bytesToCopy;
			return bytesToCopy;
		}

		bool isEndOfTransmission() const noexcept
		{
			return fileMetadataRead == static_cast<size_t>(2 + 8) && filePathSize == 0 && fileSizeBytes == 0;
		}

		void newFile() noexcept
		{
			if (isFileOpen(file))
			{
				file.close();
			}

			bytesWrittenToFile = 0;
			fileMetadataRead = 0;
			filePathSize = 0;
			fileSizeBytes = 0;
			filePath.clear();
			// set the default status to update later
			lastFileStatuses.push_back(Protocol::FileExchange::FileReceiveStatus::Success);
			debugPrintState(DebugState::NewFile);
			++currentFileIndex;
		}

		void writeFileToDiskFromBuffer()
		{
			if (fileMetadataRead < static_cast<size_t>(2 + 8 + filePathSize))
			{
				if (fileMetadataRead < 8)
				{
					debugPrintState(DebugState::FileSize);
					Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, 8> data;
					if (fileMetadataRead != 0)
					{
						Serialization::writeUint64(data, fileSizeBytes);
					}
					fileMetadataRead += partiallyReadDataFromChunk(data, fileMetadataRead);
					fileSizeBytes = Serialization::readUint64(data);
					if (isBufferFullyRead())
					{
						return;
					}
				}

				if (fileMetadataRead < 8 + 2)
				{
					debugPrintState(DebugState::FilePathSize);
					Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, 2> data;
					if (fileMetadataRead != 8)
					{
						Serialization::writeUint16(data.raw[0], data.raw[1], filePathSize);
					}
					fileMetadataRead += partiallyReadDataFromChunk(data, fileMetadataRead - 8);
					filePathSize = Serialization::readUint16(data.raw[0], data.raw[1]);

					if (isEndOfTransmission())
					{
						return;
					}

					if (isBufferFullyRead())
					{
						return;
					}
				}
				filePath.resize(filePathSize);

				fileMetadataRead += partiallyReadDataFromChunk(std::span<std::byte>(reinterpret_cast<std::byte*>(filePath.data()), filePathSize), fileMetadataRead - (8 + 2));

				// if we have not finished reading name, but buffer is full, break here to return later
				if (fileMetadataRead < static_cast<size_t>(2 + 8 + filePathSize) && isBufferFullyRead())
				{
					return;
				}

				if (Files::isFilePathAcceptable(filePath))
				{
					openFile(file, rootPath / filePath);

					if (!isFileOpen(file))
					{
						reportDebugError("Could not open file for writing {}", filePath);
						debugAssert(!lastFileStatuses.empty(), "last file statuses is not expected to be empty");
						if (!lastFileStatuses.empty())
						{
							// save the error, so we ignore writing to the file and send the status to the client
							// but otherwise continue receiving and decoding the data until the time of reporting
							lastFileStatuses.back() = Protocol::FileExchange::FileReceiveStatus::CouldNotCreate;
						}
					}
				}
				else
				{
					debugAssert(!lastFileStatuses.empty(), "last file statuses is not expected to be empty when rejecting file name");
					if (!lastFileStatuses.empty())
					{
						// save the error, so we ignore writing to the file and send the status to the client
						// but otherwise continue receiving and decoding the data until the time of reporting
						lastFileStatuses.back() = Protocol::FileExchange::FileReceiveStatus::BadFilePath;
					}
				}

				// if we finished reading metadata and the buffer if full
				if (fileMetadataRead == static_cast<size_t>(2 + 8 + filePathSize) && isBufferFullyRead())
				{
					return;
				}
			}

			if (bytesWrittenToFile == fileSizeBytes)
			{
				return;
			}

			const size_t bytesToWrite = std::min(fileSizeBytes - bytesWrittenToFile, ChunkSize - bytesReadInChunk);
			if (currentFileHasNoErrors())
			{
				debugPrintState(DebugState::FileContent);
				writeSpanIntoStream(file, std::span<std::byte>(buffer.raw.data() + bytesReadInChunk, bytesToWrite));
			}
			else
			{
				debugPrintState(DebugState::FileContentSkipped);
			}
			bytesWrittenToFile += bytesToWrite;
			bytesReadInChunk += bytesToWrite;
			assertFatalRelease(bytesWrittenToFile <= fileSizeBytes, "File read size bigger than file size, this should never happen");
		}

		[[nodiscard]] bool receiveChunk(Network::RawSocket socket, Noise::CipherStateReceiving& receivingCipherstate) noexcept
		{
			if (bytesReadInChunk != ChunkSize)
			{
				reportDebugError("We should never try reading new chunk before finishing processing the previous one");
				return false;
			}

			size_t bytesReceived = 0;
			auto readResult = recvBuffer(socket, buffer, bytesReceived, receivingCipherstate);
			if (readResult.has_value())
			{
				reportDebugError("Could not recv file part: {}", *readResult);
				return false;
			}

			if (bytesReceived != ChunkSize)
			{
				reportDebugError("Received chunk of unexpected size: {}", bytesReceived);
				return false;
			}

			Noise::Utils::rekey(receivingCipherstate);

			++chunksReceived;
			bytesReadInChunk = 0;

			debugPrintState(DebugState::StartChunk);
			return true;
		}

		void skipToTheEnd() noexcept
		{
			bytesReadInChunk = ChunkSize;
		}

		[[nodiscard]] bool shouldWriteAnswer() const noexcept
		{
			return chunksReceived != 0 && chunksReceived % ChunksBetweenAnswers == 0;
		}

		[[nodiscard]] bool writeAnswer(Network::RawSocket socket, Noise::CipherStateSending& sendingCipherstate) noexcept
		{
			// read the big comment in Protocol::FileExchange for the explanation

			constexpr size_t BitsetOffset = 2;

			debugPrintState(DebugState::Answer);

			const bool hasFileInProgress = !hasFileFinished();
			const size_t statusesToSend = lastFileStatuses.size() - (isEndOfTransmission() ? 1 : 0);

			// buffer is zeroed by default
			Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, AnswerChunkSize + Cryptography::CipherAuthDataSize> sendingBuffer;

			assertFatalRelease(statusesToSend < std::numeric_limits<uint16_t>::max(), "Too many files to confirm in one answer than ever expected {}", statusesToSend);
			Serialization::writeUint16(sendingBuffer.raw[0], sendingBuffer.raw[1], static_cast<uint16_t>(statusesToSend));

			const size_t bytesInBitset = (statusesToSend + 7) / 8;

			const size_t bitsetChunks = (BitsetOffset + bytesInBitset + AnswerChunkSize - 1) / AnswerChunkSize;

			size_t posInChunk = BitsetOffset;
			auto sendChunk = [this, socket, &sendingBuffer, &sendingCipherstate, &posInChunk] {
				if (auto result = sendAnswerBuffer(socket, sendingBuffer, AnswerChunkSize, sendingCipherstate))
				{
					reportDebugError("Could not send answer bitset chunk: {}", *result);
					return false;
				}

				Noise::Utils::rekey(sendingCipherstate);

				// clean the ciphertext from the buffer to make sure we have zeros to reuse the buffer
				std::fill(sendingBuffer.raw.begin(), sendingBuffer.raw.end(), std::byte(0x00));
				posInChunk = 0;

				return true;
			};

			size_t popcount = 0;
			size_t posInStatuses = 0;
			for (size_t chunkIdx = 0; chunkIdx < bitsetChunks; ++chunkIdx)
			{
				if (posInChunk == AnswerChunkSize)
				{
					debugPrintState(DebugState::AnswerExtraChunk);
					if (!sendChunk())
					{
						return false;
					}
				}

				for (; posInStatuses < statusesToSend && posInChunk < AnswerChunkSize; ++posInStatuses)
				{
					const size_t bit = posInStatuses % 8;
					const Protocol::FileExchange::FileReceiveStatus status = lastFileStatuses[posInStatuses];
					popcount += status == Protocol::FileExchange::FileReceiveStatus::Success ? 0 : 1;
					sendingBuffer.raw[posInChunk] |= static_cast<std::byte>(((status == Protocol::FileExchange::FileReceiveStatus::Success ? 0 : 1) << (7 - bit)));

					if (posInStatuses % 8 == 7)
					{
						++posInChunk;
					}
				}
			}

			if (posInStatuses % 8 != 0)
			{
				++posInChunk;
			}

			const size_t errorsArrayOffset = posInChunk;
			const size_t errorsArraySize = popcount;
			assertFatalRelease(posInChunk == (BitsetOffset + bytesInBitset) % AnswerChunkSize || posInChunk == AnswerChunkSize, "Unexpected chunk pos {} == {}", posInChunk, (BitsetOffset + bytesInBitset) % AnswerChunkSize);

			const size_t chunksToSend = (errorsArrayOffset + errorsArraySize + AnswerChunkSize - 1) / AnswerChunkSize;

			// if we don't have anything to send, pretent that we have iterated over the array
			posInStatuses = popcount != 0 ? 0 : statusesToSend;
			for (size_t i = 0; i < chunksToSend; ++i)
			{
				for (; posInStatuses < statusesToSend && posInChunk < AnswerChunkSize; ++posInStatuses)
				{
					if (lastFileStatuses[posInStatuses] != Protocol::FileExchange::FileReceiveStatus::Success)
					{
						sendingBuffer.raw[posInChunk] = static_cast<std::byte>(lastFileStatuses[posInStatuses]);
						++posInChunk;
					}
				}

				if (i + 1 == chunksToSend)
				{
					// end of last chunk
					assertFatalRelease(posInStatuses <= statusesToSend, "Have sent unexpected number of statuses {} of {}", posInStatuses, statusesToSend);
					assertFatalRelease(posInChunk == (errorsArrayOffset + errorsArraySize) % AnswerChunkSize || posInChunk == AnswerChunkSize, "Unexpected chunk size for the last chunk {} == {}", posInChunk, (errorsArrayOffset + errorsArraySize) % AnswerChunkSize);
				}
				else
				{
					assertFatalRelease(posInChunk == AnswerChunkSize, "Unexpected chunk size {}", posInChunk);
				}

#ifdef DEBUG_CHECKS
				if (i + 1 != chunksToSend)
				{
					debugPrintState(DebugState::AnswerExtraChunk);
				}
#endif // DEBUG_CHECKS

				if (!sendChunk())
				{
					return false;
				}
			}

			const bool hasFileInProgressFailed = hasFileInProgress && !currentFileHasNoErrors();

			lastFileStatuses.clear();
			if (hasFileInProgressFailed)
			{
				// reset receiving of the last file
				newFile();
			}
			else if (hasFileInProgress)
			{
				// restore the record for the file that is in progress, or that is about to be written
				lastFileStatuses.push_back(Protocol::FileExchange::FileReceiveStatus::Success);
			}

			return true;
		}
	};

	void receiveFiles(const std::filesystem::path& targetDirectory, Network::RawSocket socket, Noise::CipherStateSending& sendingCipherstate, Noise::CipherStateReceiving& receivingCipherstate, [[maybe_unused]] Mocks mocks)
	{
		FileReceivingState receivingState;
		receivingState.rootPath = targetDirectory;

#ifdef WITH_TESTS
		receivingState.mocks = std::move(mocks);
#endif

		try
		{
			receivingState.newFile();

			if (!receivingState.receiveChunk(socket, receivingCipherstate))
			{
				return;
			}

			while (true)
			{
				receivingState.writeFileToDiskFromBuffer();

#ifdef DEBUG_CHECKS
				if (receivingState.hasFileFinished())
				{
					receivingState.debugPrintState(FileReceivingState::DebugState::EndFile);
				}
#endif // DEBUG_CHECKS

				if (receivingState.isEndOfTransmission())
				{
					break;
				}

				if (receivingState.isBufferFullyRead())
				{
					receivingState.debugPrintState(FileReceivingState::DebugState::EndChunk);

					if (receivingState.shouldWriteAnswer())
					{
						if (!receivingState.writeAnswer(socket, sendingCipherstate))
						{
							return;
						}
					}

					if (!receivingState.receiveChunk(socket, receivingCipherstate))
					{
						return;
					}
				}

				if (receivingState.hasFileFinished())
				{
					receivingState.newFile();
				}
			}

			receivingState.debugPrintState(FileReceivingState::DebugState::EndChunk);

			if (receivingState.haveUnconfirmedFiles())
			{
				if (!receivingState.writeAnswer(socket, sendingCipherstate))
				{
					return;
				}
			}
		}
		catch (std::exception& e)
		{
			reportDebugError("An exception caught when receiving files: {}", e.what());
			return;
		}
		catch (...)
		{
			reportDebugError("An exception caught when receiving files");
			return;
		}
	}
} // namespace FileReceiveUtils
