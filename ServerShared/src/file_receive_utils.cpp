// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/file_receive_utils.h"

#include <fstream>
#include <limits>

#include "common_shared/cryptography/noise/cipher_utils.h"
#include "common_shared/debug/assert.h"
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
		};

		void debugPrintState([[maybe_unused]] DebugState state)
		{
#ifdef DEBUG_CHECKS
			if constexpr (debugPrint)
			{
				switch (state)
				{
				case DebugState::StartChunk:
					Debug::Log::printDebug("Receive:\t\t\t  /---------------\\\nReceive:\t\t\t /                 \\");
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
			return filePathSize == 0 && fileSizeBytes == 0;
		}

		static bool isFilePathAcceptable(const std::filesystem::path& path) noexcept
		{
			if (path.empty())
			{
				return false;
			}

			if (path.is_absolute())
			{
				return false;
			}

			// make sure the path doesn't contain /./ and /../ parts in the middle
			if (path.lexically_normal() != path)
			{
				return false;
			}

			// check that the path doesn't start with ..
			std::filesystem::path parent = path;
			while (parent.has_parent_path())
			{
				parent = parent.parent_path();
			}
			return parent != "..";
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
		}

		[[nodiscard]] bool writeFileToDiskFromBuffer()
		{
			if (isBufferFullyRead())
			{
				debugPrintState(DebugState::EndChunk);
				return true;
			}

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
						debugPrintState(DebugState::EndChunk);
						return true;
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

					if (fileMetadataRead == static_cast<size_t>(2 + 8) && filePathSize == 0 && fileSizeBytes == 0)
					{
						// this is a signal about the transmission end, return as if we finished reading the file
						debugPrintState(DebugState::EndTransmission);
						return false;
					}

					if (isBufferFullyRead())
					{
						debugPrintState(DebugState::EndChunk);
						return true;
					}
				}
				filePath.resize(filePathSize);

				debugPrintState(DebugState::FilePath);
				fileMetadataRead += partiallyReadDataFromChunk(std::span<std::byte>(reinterpret_cast<std::byte*>(filePath.data()), filePathSize), fileMetadataRead - (8 + 2));

				// if we have not finished reading name, but buffer is full, break here to return later
				if (fileMetadataRead < static_cast<size_t>(2 + 8 + filePathSize) && isBufferFullyRead())
				{
					debugPrintState(DebugState::EndChunk);
					return true;
				}

				if (isFilePathAcceptable(filePath))
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
					// save the error, so we ignore writing to the file and send the status to the client
					// but otherwise continue receiving and decoding the data until the time of reporting
					lastFileStatuses.back() = Protocol::FileExchange::FileReceiveStatus::BadFilePath;
				}

				// if we finished reading metadata and the buffer if full
				if (fileMetadataRead == static_cast<size_t>(2 + 8 + filePathSize) && isBufferFullyRead())
				{
					debugPrintState(DebugState::EndChunk);
					return true;
				}
			}

			if (bytesWrittenToFile == fileSizeBytes)
			{
				debugPrintState(DebugState::EndFile);
				return false;
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

			debugPrintState(bytesWrittenToFile != fileSizeBytes ? DebugState::EndChunk : DebugState::EndFile);
			return bytesWrittenToFile != fileSizeBytes;
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

			const bool hasFileInProgress = !hasFileFinished();
			const size_t statusesToSend = lastFileStatuses.size();
			// buffer is zeroed by default
			Cryptography::ByteSequence<Cryptography::ByteSequenceTag::TempInternalBuffer, AnswerChunkSize + Cryptography::CipherAuthDataSize> sendingBuffer;

			assertFatalRelease(statusesToSend < std::numeric_limits<uint16_t>::max(), "Too many files to confirm in one answer than ever expected {}", statusesToSend);
			Serialization::writeUint16(sendingBuffer.raw[0], sendingBuffer.raw[1], static_cast<uint16_t>(statusesToSend));

			const size_t bytesInBitset = (statusesToSend + 7) / 8;

			assertFatalRelease(BitsetOffset + bytesInBitset < AnswerChunkSize, "We expected to never have a bitset that won't fit into the first chunk of the answer message, bitset size was {}", bytesInBitset);

			size_t popcount = 0;
			for (size_t i = 0; i < statusesToSend; ++i)
			{
				const size_t byte = i / 8;
				const size_t bit = i % 8;
				popcount += lastFileStatuses[i] == Protocol::FileExchange::FileReceiveStatus::Success ? 0 : 1;
				sendingBuffer.raw[2 + byte] |= static_cast<std::byte>(((lastFileStatuses[i] == Protocol::FileExchange::FileReceiveStatus::Success ? 0 : 1) << (7 - bit)));
			}

			const size_t errorsArrayOffset = BitsetOffset + bytesInBitset;
			const size_t errorsArraySize = popcount;

			const size_t chunksToSend = (errorsArrayOffset + errorsArraySize + AnswerChunkSize - 1) / AnswerChunkSize;
			assertFatalRelease(chunksToSend != 0, "Can't have zero chunks to send as an answer");

			size_t posInChunk = errorsArrayOffset;
			size_t posInStatuses = 0;
			for (size_t i = 0; i < chunksToSend; ++i)
			{
				for (; posInStatuses < statusesToSend; ++posInStatuses)
				{
					if (lastFileStatuses[posInStatuses] != Protocol::FileExchange::FileReceiveStatus::Success)
					{
						sendingBuffer.raw[posInChunk] = static_cast<std::byte>(lastFileStatuses[posInStatuses]);
						++posInChunk;
						if (posInChunk == AnswerChunkSize)
						{
							break;
						}
					}
				}

				if (auto result = sendAnswerBuffer(socket, sendingBuffer, AnswerChunkSize, sendingCipherstate))
				{
					reportDebugError("Could not send an answer chunk {}: {}", i, *result);
					return false;
				}

				if (i + 1 != chunksToSend)
				{
					std::fill(sendingBuffer.raw.begin(), sendingBuffer.raw.end(), std::byte(0));
					assertFatalRelease(posInChunk == AnswerChunkSize, "Unexpected chunk size {}", posInChunk);
					posInChunk = 0;
				}
				else
				{
					// end of last chunk
					assertFatalRelease(posInStatuses <= statusesToSend, "Have read more statuses than available {} of {}", posInStatuses, statusesToSend);
					assertFatalRelease(posInChunk == (errorsArraySize + errorsArrayOffset) % AnswerChunkSize, "Unexpected chunk size for the last chunk {}", posInChunk);
				}
			}

			const bool hasFileInProgressFailed = hasFileInProgress && !currentFileHasNoErrors();

			debugPrintState(DebugState::Answer);

			lastFileStatuses.clear();
			if (hasFileInProgressFailed)
			{
				newFile();
			}
			else
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

		Debug::Log::printDebug("start receiving files");

		try
		{
			receivingState.newFile();

			if (!receivingState.receiveChunk(socket, receivingCipherstate))
			{
				return;
			}

			while (true)
			{
				while (receivingState.writeFileToDiskFromBuffer())
				{
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

				if (receivingState.isEndOfTransmission())
				{
					break;
				}

				receivingState.newFile();
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
		catch (...)
		{
			reportDebugError("An exception caught when receiving files");
			return;
		}
	}
} // namespace FileReceiveUtils
