// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "server_shared/file_receive_utils.h"

#include <fstream>

#include "common_shared/cryptography/noise/cipher_utils.h"
#include "common_shared/debug/assert.h"
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
	/// An answer is sent each 32 chunks (but can be read one chunk later), or at the end of the transmission.
	struct FileReceivingState
	{
		constexpr static size_t ChunkSize = 1024;
		constexpr static size_t ChunksBetweenAnswers = 32;

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
		size_t fileIndex = 0;

		[[nodiscard]] bool isBufferFullyRead() const noexcept
		{
			return bytesReadInChunk == ChunkSize;
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

		void newFile() noexcept
		{
			if (file.is_open())
			{
				file.close();
			}

			bytesWrittenToFile = 0;
			fileMetadataRead = 0;
			filePathSize = 0;
			fileSizeBytes = 0;
			filePath.clear();
			++fileIndex;
		}

		[[nodiscard]] bool writeFileToDiskFromBuffer()
		{
			// if it happens that we have finished both writing to the file and reading from the buffer
			if (isBufferFullyRead())
			{
				return true;
			}

			if (fileMetadataRead < static_cast<size_t>(2 + 8 + filePathSize))
			{
				if (fileMetadataRead < 8)
				{
					std::array<std::byte, 8> data;
					if (fileMetadataRead != 0)
					{
						Serialization::writeUint64(data, fileSizeBytes);
					}
					fileMetadataRead += partiallyReadDataFromChunk(data, fileMetadataRead);
					fileSizeBytes = Serialization::readUint64(data);
					if (isBufferFullyRead())
					{
						return true;
					}
				}

				if (fileMetadataRead < 8 + 2)
				{
					std::array<std::byte, 2> data;
					if (fileMetadataRead != 8)
					{
						Serialization::writeUint16(data[0], data[1], filePathSize);
					}
					fileMetadataRead += partiallyReadDataFromChunk(data, fileMetadataRead - 8);
					filePathSize = Serialization::readUint16(data[0], data[1]);

					if (fileMetadataRead == static_cast<size_t>(2 + 8) && filePathSize == 0 && fileSizeBytes == 0)
					{
						// this is a signal about the transmission end, return as if we finished reading the file
						return false;
					}

					if (isBufferFullyRead())
					{
						return true;
					}
				}
				filePath.resize(filePathSize);

				fileMetadataRead += partiallyReadDataFromChunk(std::span<std::byte>(reinterpret_cast<std::byte*>(filePath.data()), filePathSize), fileMetadataRead - (8 + 2));

				// if we have not finished reading name, but buffer is full, break here to return later
				if (fileMetadataRead < static_cast<size_t>(2 + 8 + filePathSize) && isBufferFullyRead())
				{
					return true;
				}

				// ToDo: sanitize the path

				file.open(rootPath / filePath, std::ios::binary | std::ios::out);

				if (!file.is_open())
				{
					reportDebugError("Could not open file for writing {}", filePath);
					// ToDo: report unsuccessful file saving
					// for now signal about transmission end
					filePathSize = 0;
					fileSizeBytes = 0;
					return false;
				}

				// if we finished reading metadata and the buffer if full
				if (fileMetadataRead == static_cast<size_t>(2 + 8 + filePathSize) && isBufferFullyRead())
				{
					return true;
				}
			}

			if (bytesWrittenToFile == fileSizeBytes)
			{
				return false;
			}

			const size_t bytesToWrite = std::min(fileSizeBytes - bytesWrittenToFile, ChunkSize - bytesReadInChunk);
			file.write(reinterpret_cast<char*>(buffer.raw.data() + bytesReadInChunk), bytesToWrite);
			bytesWrittenToFile += bytesToWrite;
			bytesReadInChunk += bytesToWrite;
			assertFatalRelease(bytesWrittenToFile <= fileSizeBytes, "File read size bigger than file size, this should never happen");

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
			auto readResult = Network::recvEncrypted(socket, buffer, bytesReceived, receivingCipherstate);
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

			return true;
		}

		[[nodiscard]] bool shouldWriteAnswer() const noexcept
		{
			return chunksReceived % ChunksBetweenAnswers;
		}

		void skipToTheEnd() noexcept
		{
			bytesReadInChunk = ChunkSize;
		}
	};

	void receiveFiles(const std::filesystem::path& targetDirectory, Network::RawSocket socket, Noise::CipherStateSending& /*sendingCipherstate*/, Noise::CipherStateReceiving& receivingCipherstate)
	{
		FileReceivingState receivingState;
		receivingState.rootPath = targetDirectory;

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
					if (!receivingState.receiveChunk(socket, receivingCipherstate))
					{
						return;
					}

					if (receivingState.shouldWriteAnswer())
					{
						// ToDo: write answer
					}
				}

				if (receivingState.isEndOfTransmission())
				{
					break;
				}

				receivingState.newFile();
			}

			// ToDo: write answer
		}
		catch (...)
		{
			reportDebugError("An exception caught when receiving files");
			return;
		}
	}
} // namespace FileReceiveUtils
