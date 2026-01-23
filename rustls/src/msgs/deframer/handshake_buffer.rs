//! Handshake buffer for zero-copy API
//!
//! This module provides `HandshakeBuffer`, a simplified handshake message manager
//! designed for the zero-copy API. Unlike `HandshakeDeframer`, data is appended
//! contiguously without requiring coalescing or Locator/Delocator mechanisms.

use alloc::vec;
use alloc::vec::Vec;

use crate::enums::{ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::message::InboundPlainMessage;

const HANDSHAKE_HEADER_LEN: usize = 4;
const DEFAULT_HS_BUFFER_SIZE: usize = 64 * 1024; // 64KB initial size
const MAX_HS_BUFFER_SIZE: usize = 256 * 1024; // 256KB max (sufficient for large Certificate chains)

/// Handshake message buffer for zero-copy API
///
/// Manages a dynamic internal buffer for storing and parsing handshake messages.
/// Unlike `HandshakeDeframer`:
/// - Data is appended contiguously, no coalescing required
/// - No Locator/Delocator mechanisms needed
/// - Lifecycle managed internally by this struct
/// - Buffer grows dynamically (64KB initial, 256KB max)
pub(crate) struct HandshakeBuffer {
    /// Internal buffer storing handshake message data (dynamic growth)
    buffer: Vec<u8>,

    /// Next write position (bytes written so far)
    write_pos: usize,

    /// Next read position (bytes consumed so far)
    read_pos: usize,

    /// Current protocol version (obtained from first message)
    pub(crate) version: Option<ProtocolVersion>,
}

impl Default for HandshakeBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeBuffer {
    /// Create a new handshake buffer (initial 64KB)
    pub(crate) fn new() -> Self {
        Self {
            buffer: vec![0u8; DEFAULT_HS_BUFFER_SIZE],
            write_pos: 0,
            read_pos: 0,
            version: None,
        }
    }

    /// Create with specified initial size
    #[allow(dead_code)]
    pub(crate) fn with_capacity(size: usize) -> Self {
        Self {
            buffer: vec![0u8; size],
            write_pos: 0,
            read_pos: 0,
            version: None,
        }
    }

    // =========================================================================
    // Internal helper methods
    // =========================================================================

    /// Length of pending (unread) data
    fn pending_len(&self) -> usize {
        self.write_pos - self.read_pos
    }

    /// Slice of pending (unread) data
    pub(crate) fn pending(&self) -> &[u8] {
        &self.buffer[self.read_pos..self.write_pos]
    }

    /// Available write space
    fn available_space(&self) -> usize {
        self.buffer.len() - self.write_pos
    }

    /// Try to parse the total length of the next message (header + body)
    ///
    /// Returns None if there's insufficient data to read the header
    fn peek_message_len(&self) -> Option<usize> {
        let pending = self.pending();
        if pending.len() < HANDSHAKE_HEADER_LEN {
            return None;
        }
        // Parse u24 length (header[1..4], big-endian)
        let len = u32::from_be_bytes([0, pending[1], pending[2], pending[3]]) as usize;
        Some(HANDSHAKE_HEADER_LEN + len)
    }

    /// Compact the buffer by removing consumed data to free up space
    fn compact(&mut self) {
        if self.read_pos > 0 {
            self.buffer
                .copy_within(self.read_pos..self.write_pos, 0);
            self.write_pos -= self.read_pos;
            self.read_pos = 0;
        }
    }

    // =========================================================================
    // Public methods: Append data
    // =========================================================================

    /// Append handshake payload to the buffer
    ///
    /// # Arguments
    /// * `payload` - Handshake message payload (may be partial message)
    /// * `version` - Protocol version
    ///
    /// # Returns
    /// * `Ok(())` - Successfully appended
    /// * `Err(Error)` - Buffer overflow (exceeds max limit)
    pub(crate) fn append(&mut self, payload: &[u8], version: ProtocolVersion) -> Result<(), Error> {
        // Always update version to use the latest received version
        // This is important for TLS 1.3 where early handshake messages are plaintext (TLS 1.2 record version)
        // but encrypted handshake messages have TLSv1_3 version set by decrypt_to
        self.version = Some(version);

        // Check if space is sufficient
        if self.available_space() < payload.len() {
            // Try compacting (remove consumed data)
            self.compact();

            // Check again, expand if still insufficient
            if self.available_space() < payload.len() {
                let needed = self.write_pos + payload.len();
                if needed > MAX_HS_BUFFER_SIZE {
                    return Err(Error::General(
                        "handshake buffer overflow (exceeds 256KB)".into(),
                    ));
                }
                // Expand buffer
                let new_size = needed
                    .next_power_of_two()
                    .min(MAX_HS_BUFFER_SIZE);
                self.buffer.resize(new_size, 0);
            }
        }

        // Append data
        self.buffer[self.write_pos..self.write_pos + payload.len()].copy_from_slice(payload);
        self.write_pos += payload.len();

        Ok(())
    }

    // =========================================================================
    // Public methods: State queries
    // =========================================================================

    /// Is there a complete handshake message ready to read?
    ///
    /// Returns true if the buffer contains a complete header + body
    pub(crate) fn has_message_ready(&self) -> bool {
        self.peek_message_len()
            .is_some_and(|len| self.pending_len() >= len)
    }

    /// Is there any data (complete or partial)?
    ///
    /// Returns true if the buffer is not empty
    pub(crate) fn is_active(&self) -> bool {
        self.pending_len() > 0
    }

    /// Is the buffer aligned (no partial messages)?
    ///
    /// Definition of aligned:
    /// - Buffer is empty, OR
    /// - All data forms complete handshake messages (no residual)
    ///
    /// This is important for ensuring handshake messages don't interleave with other record types.
    pub(crate) fn is_aligned(&self) -> bool {
        let mut offset = 0;
        let pending = self.pending();

        while offset < pending.len() {
            // Check for complete header
            if pending.len() - offset < HANDSHAKE_HEADER_LEN {
                return false; // Incomplete header
            }

            // Parse body length
            let len = u32::from_be_bytes([
                0,
                pending[offset + 1],
                pending[offset + 2],
                pending[offset + 3],
            ]) as usize;

            let msg_len = HANDSHAKE_HEADER_LEN + len;

            // Check for complete body
            if pending.len() - offset < msg_len {
                return false; // Incomplete body
            }

            offset += msg_len;
        }

        true
    }

    // =========================================================================
    // Public methods: Read messages
    // =========================================================================

    /// Read the next complete handshake message
    ///
    /// Returns `InboundPlainMessage` borrowing the internal buffer.
    /// Calling this method consumes the message (moves read_pos).
    ///
    /// # Returns
    /// * `Some(message)` - Complete message available
    /// * `None` - No complete message
    ///
    /// # Note
    /// The returned message's payload lifetime is tied to self.
    pub(crate) fn next_message(&mut self) -> Option<InboundPlainMessage<'_>> {
        let msg_len = self.peek_message_len()?;

        if self.pending_len() < msg_len {
            return None;
        }

        let start = self.read_pos;
        let end = start + msg_len;
        let payload = &self.buffer[start..end];

        // Consume message
        self.read_pos = end;

        Some(InboundPlainMessage {
            typ: ContentType::Handshake,
            version: self
                .version
                .unwrap_or(ProtocolVersion::TLSv1_2),
            payload,
        })
    }

    /// Clear the buffer
    ///
    /// Resets all state, can be used to release resources after handshake completion.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
        self.version = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_buffer() {
        let buf = HandshakeBuffer::new();
        assert!(!buf.is_active());
        assert!(buf.is_aligned());
        assert!(!buf.has_message_ready());
    }

    #[test]
    fn test_append_and_read() {
        let mut buf = HandshakeBuffer::new();

        // Handshake message: type=1 (ClientHello), length=5, body=[0,1,2,3,4]
        let msg = [1, 0, 0, 5, 0, 1, 2, 3, 4];
        buf.append(&msg, ProtocolVersion::TLSv1_3)
            .unwrap();

        assert!(buf.is_active());
        assert!(buf.is_aligned());
        assert!(buf.has_message_ready());

        let message = buf.next_message().unwrap();
        assert_eq!(message.typ, ContentType::Handshake);
        assert_eq!(message.version, ProtocolVersion::TLSv1_3);
        assert_eq!(message.payload, &msg);

        assert!(!buf.is_active());
        assert!(!buf.has_message_ready());
    }

    #[test]
    fn test_partial_message() {
        let mut buf = HandshakeBuffer::new();

        // Partial header only
        buf.append(&[1, 0, 0], ProtocolVersion::TLSv1_3)
            .unwrap();
        assert!(buf.is_active());
        assert!(!buf.is_aligned()); // Incomplete header
        assert!(!buf.has_message_ready());

        // Complete header, partial body
        buf.append(&[5, 0, 1], ProtocolVersion::TLSv1_3)
            .unwrap();
        assert!(buf.is_active());
        assert!(!buf.is_aligned()); // Incomplete body
        assert!(!buf.has_message_ready());

        // Complete body
        buf.append(&[2, 3, 4], ProtocolVersion::TLSv1_3)
            .unwrap();
        assert!(buf.is_active());
        assert!(buf.is_aligned());
        assert!(buf.has_message_ready());
    }

    #[test]
    fn test_multiple_messages() {
        let mut buf = HandshakeBuffer::new();

        // Two messages
        let msg1 = [1, 0, 0, 2, 0xAA, 0xBB];
        let msg2 = [2, 0, 0, 3, 0xCC, 0xDD, 0xEE];

        buf.append(&msg1, ProtocolVersion::TLSv1_3)
            .unwrap();
        buf.append(&msg2, ProtocolVersion::TLSv1_3)
            .unwrap();

        assert!(buf.is_aligned());
        assert!(buf.has_message_ready());

        let m1 = buf.next_message().unwrap();
        assert_eq!(m1.payload, &msg1);

        let m2 = buf.next_message().unwrap();
        assert_eq!(m2.payload, &msg2);

        assert!(!buf.has_message_ready());
    }

    #[test]
    fn test_buffer_growth() {
        let mut buf = HandshakeBuffer::with_capacity(16);

        // Fill with data requiring growth
        let header = [1, 0, 0, 20]; // length = 20
        let body = [0u8; 20];

        buf.append(&header, ProtocolVersion::TLSv1_3)
            .unwrap();
        buf.append(&body, ProtocolVersion::TLSv1_3)
            .unwrap();

        assert!(buf.buffer.len() > 16); // Buffer grew
        assert!(buf.has_message_ready());
    }
}
