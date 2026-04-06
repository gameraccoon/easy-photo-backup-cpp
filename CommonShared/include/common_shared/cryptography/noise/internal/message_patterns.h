// Copyright (C) Pavel Grebnev 2026
// Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).

#pragma once

#include <optional>

#include "common_shared/cryptography/noise/handshake_types.h"

namespace Noise::MessagePatterns
{
	// -> e
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_e_initiator(InitiatorHandshakeState& handshakeState, const std::span<std::byte> outMessageBuffer, size_t& inOutCursor) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_e_responder(ResponderHandshakeState& handshakeState, const std::span<const std::byte> messageData, size_t& inOutCursor) noexcept;

	// <- e
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_e_responder(ResponderHandshakeState& handshakeState, const std::span<std::byte> outMessageBuffer, size_t& inOutCursor) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_e_initiator(InitiatorHandshakeState& handshakeState, const std::span<const std::byte> messageData, size_t& inOutCursor) noexcept;

	// -> s
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_s_initiator(InitiatorHandshakeState& handshakeState, const std::span<std::byte> outMessageBuffer, size_t& inOutCursor) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_s_responder(ResponderHandshakeState& handshakeState, const std::span<const std::byte> messageData, size_t& inOutCursor) noexcept;

	// <- s
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_s_responder(ResponderHandshakeState& handshakeState, const std::span<std::byte> outMessageBuffer, size_t& inOutCursor) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_s_initiator(InitiatorHandshakeState& handshakeState, const std::span<const std::byte> messageData, size_t& inOutCursor) noexcept;

	// -> ee
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_ee_initiator(InitiatorHandshakeState& handshakeState) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_ee_responder(ResponderHandshakeState& handshakeState) noexcept;

	// <- ee
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_ee_responder(ResponderHandshakeState& handshakeState) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_ee_initiator(InitiatorHandshakeState& handshakeState) noexcept;

	// -> es
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_es_initiator(InitiatorHandshakeState& handshakeState) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_es_responder(ResponderHandshakeState& handshakeState) noexcept;

	// <- es
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_es_responder(ResponderHandshakeState& handshakeState) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_es_initiator(InitiatorHandshakeState& handshakeState) noexcept;

	// -> se
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_se_initiator(InitiatorHandshakeState& handshakeState) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_se_responder(ResponderHandshakeState& handshakeState) noexcept;

	// <- se
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_se_responder(ResponderHandshakeState& handshakeState) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_se_initiator(InitiatorHandshakeState& handshakeState) noexcept;

	// -> ss
	[[nodiscard]] std::optional<MessageWriteError> writeMessagePattern_ss_initiator(InitiatorHandshakeState& handshakeState) noexcept;
	[[nodiscard]] std::optional<MessageReadError> readMessagePattern_ss_responder(ResponderHandshakeState& handshakeState) noexcept;
} // namespace Noise::MessagePatterns
