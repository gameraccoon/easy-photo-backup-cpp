// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#include "client_shared/file_send_utils.h"

#include <fstream>

#include "common_shared/cryptography/noise/cipher_utils.h"
#include "common_shared/debug/assert.h"
#include "common_shared/network/protocol.h"
#include "common_shared/network/utils.h"
#include "common_shared/serialization/number_serialization.h"

namespace FileSendUtils
{
	/// Files are sent in chunks of 1024 bytes + auth data,
	/// each message is encrypted separately,
	/// rekey is called after each message,
	/// no out-of-order messages allowed.
	/// If the file size does not align to 1024, the next file will be written right after
	/// in the same message if possible. All messages below 1024 bytes are padded with zeroes at the end.
	/// An answer is sent each 32 chunks (but can be read one chunk later), or at the end of the transmission.
	struct FileSendingState
	{
		constexpr static size_t ChunkSize = Protocol::FileExchange::ChunkSize;
		constexpr static size_t ChunksBetweenAnswers = Protocol::FileExchange::ChunksBetweenAnswers;

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

		[[nodiscard]] bool isBufferEmpty() const noexcept
		{
			return bytesFilledInChunk == 0;
		}

		[[nodiscard]] bool isBufferFull() const noexcept
		{
			return bytesFilledInChunk == ChunkSize;
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

			stream.read(reinterpret_cast<char*>(bufferSpan.data()), buffer.size());
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
				outPaths.push_back(dirEntry.path());
			}
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
			++fileIndex;
		}

		[[nodiscard]] bool readFileIntoBuffer(std::ifstream& file) noexcept
		{
			// if it happens that we have finished both reading the file and writing to the buffer
			if (isBufferFull())
			{
				return true;
			}

			if (fileMetadataWritten < fileMetadataBytes)
			{
				if (fileMetadataWritten < 8)
				{
					std::array<std::byte, 8> data;
					Serialization::writeUint64(data, fileSizeBytes);
					fileMetadataWritten += partiallyWriteDataToChunk(data, fileMetadataWritten);
					if (isBufferFull())
					{
						return true;
					}
				}

				if (fileMetadataWritten < 8 + 2)
				{
					std::array<std::byte, 2> data;
					Serialization::writeUint16(data[0], data[1], filePathSize);
					fileMetadataWritten += partiallyWriteDataToChunk(data, fileMetadataWritten - 8);
					if (isBufferFull())
					{
						return true;
					}
				}

				fileMetadataWritten += partiallyWriteDataToChunk(std::span<std::byte>(reinterpret_cast<std::byte*>(filePath.data()), filePathSize), fileMetadataWritten - (8 + 2));
				if (isBufferFull())
				{
					return true;
				}
			}

			const size_t bytesToRead = std::min(fileSizeBytes - bytesReadFromFile, ChunkSize - bytesFilledInChunk);
			readFileStreamIntoSpan(file, std::span(buffer.raw.data() + bytesFilledInChunk, bytesToRead));
			bytesReadFromFile += bytesToRead;
			bytesFilledInChunk += bytesToRead;
			assertFatalRelease(bytesReadFromFile <= fileSizeBytes, "File read size bigger than file size, this should never happen");
			return bytesReadFromFile != fileSizeBytes;
		}

		[[nodiscard]] bool sendChunk(Network::RawSocket socket, Noise::CipherStateSending& sendingCipherstate) noexcept
		{
			if (bytesFilledInChunk != ChunkSize)
			{
				reportDebugError("We should never try to send partially filled chunks, should use fillRemainderWithZeroes");
				return false;
			}

			auto sendResult = sendBuffer(socket, buffer, bytesFilledInChunk, sendingCipherstate);
			if (sendResult.has_value())
			{
				reportDebugError("Could not send file part: {}", *sendResult);
				return false;
			}

			Noise::Utils::rekey(sendingCipherstate);

			++chunksSent;
			bytesFilledInChunk = 0;

			return true;
		}

		[[nodiscard]] bool shouldReadAnswer() const noexcept
		{
			return chunksSent % ChunksBetweenAnswers;
		}

		void fillRemainderWithZeroes() noexcept
		{
			std::fill(buffer.raw.begin() + bytesFilledInChunk, buffer.raw.end(), std::byte(0x00));
			bytesFilledInChunk = ChunkSize;
		}
	};

	void sendDirectory(const std::filesystem::path& directoryPath, Network::RawSocket socket, Noise::CipherStateSending& sendingCipherstate, Noise::CipherStateReceiving& /*receivingCipherState*/, [[maybe_unused]] Mocks mocks) noexcept
	{
		FileSendingState sendingState;

#ifdef WITH_TESTS
		sendingState.mocks = std::move(mocks);
#endif

		Debug::Log::printDebug("start sending files");

		std::vector<std::filesystem::path> files;
		sendingState.getAllFiles(directoryPath, files);

		try
		{
			for (const auto& dirEntry : files)
			{
				std::ifstream file;
				sendingState.openFile(file, dirEntry);

				if (!sendingState.isFileOpen(file))
				{
					reportDebugError("Could not open file for reading: {}", dirEntry.string());
					return;
				}

				sendingState.newFile(dirEntry.filename(), sendingState.getFileLength(file));

				while (sendingState.readFileIntoBuffer(file))
				{
					if (!sendingState.sendChunk(socket, sendingCipherstate))
					{
						return;
					}

					if (sendingState.shouldReadAnswer())
					{
						// ToDo: read answer
					}
				}

				if (sendingState.isBufferFull())
				{
					if (!sendingState.sendChunk(socket, sendingCipherstate))
					{
						return;
					}

					if (sendingState.shouldReadAnswer())
					{
						// ToDo: read answer
					}
				}
			}

			// append 10 zero bytes (empty file with empty path) to signal about the transmission end
			{
				size_t endingBytesWritten = 0;
				std::array<std::byte, 10> endingBytes = {};
				while (endingBytesWritten < endingBytes.size())
				{
					endingBytesWritten += sendingState.partiallyWriteDataToChunk(endingBytes, endingBytesWritten);
					if (sendingState.isBufferFull())
					{
						if (!sendingState.sendChunk(socket, sendingCipherstate))
						{
							return;
						}

						if (sendingState.shouldReadAnswer())
						{
							// ToDo: read answer
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
					return;
				}

				// ToDo: read answer
			}
		}
		catch (...)
		{
			reportDebugError("An exception caught when sending files");
			return;
		}
	}
} // namespace FileSendUtils
