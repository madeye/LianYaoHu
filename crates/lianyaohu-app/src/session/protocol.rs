//! Framing for the client ↔ session-daemon socket. Byte-oriented and tiny:
//! one type byte, a u32 big-endian payload length, then the payload. Both
//! sides feed received bytes into a [`Decoder`] and pull complete frames.

use lianyaohu_core::{Result, err};

/// Upper bound on a single frame payload. Terminal I/O arrives in small
/// chunks; anything near this size is a protocol violation, not data.
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    /// Client → daemon: keystrokes for the agent's PTY.
    Input(Vec<u8>),
    /// Client → daemon: the client terminal's size.
    Resize { rows: u16, cols: u16 },
    /// Client → daemon: terminate the agent.
    Kill,
    /// Daemon → client: agent output (scrollback replay on attach, then live).
    Output(Vec<u8>),
    /// Daemon → client: the agent exited with this status.
    Exited(i32),
}

impl Frame {
    fn type_byte(&self) -> u8 {
        match self {
            Frame::Input(_) => b'I',
            Frame::Resize { .. } => b'W',
            Frame::Kill => b'K',
            Frame::Output(_) => b'O',
            Frame::Exited(_) => b'X',
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let payload: Vec<u8> = match self {
            Frame::Input(bytes) | Frame::Output(bytes) => bytes.clone(),
            Frame::Resize { rows, cols } => {
                let mut bytes = rows.to_be_bytes().to_vec();
                bytes.extend_from_slice(&cols.to_be_bytes());
                bytes
            }
            Frame::Kill => Vec::new(),
            Frame::Exited(code) => code.to_be_bytes().to_vec(),
        };
        let mut encoded = Vec::with_capacity(5 + payload.len());
        encoded.push(self.type_byte());
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&payload);
        encoded
    }

    fn decode(type_byte: u8, payload: &[u8]) -> Result<Self> {
        match type_byte {
            b'I' => Ok(Frame::Input(payload.to_vec())),
            b'O' => Ok(Frame::Output(payload.to_vec())),
            b'W' => {
                if payload.len() != 4 {
                    return Err(err("invalid resize frame"));
                }
                Ok(Frame::Resize {
                    rows: u16::from_be_bytes([payload[0], payload[1]]),
                    cols: u16::from_be_bytes([payload[2], payload[3]]),
                })
            }
            b'K' => {
                if !payload.is_empty() {
                    return Err(err("invalid kill frame"));
                }
                Ok(Frame::Kill)
            }
            b'X' => {
                if payload.len() != 4 {
                    return Err(err("invalid exit frame"));
                }
                Ok(Frame::Exited(i32::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ])))
            }
            other => Err(err(format!("unknown frame type {other:#04x}"))),
        }
    }
}

/// Incremental frame decoder over a growing byte buffer.
#[derive(Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Pops the next complete frame, or `None` when more bytes are needed.
    /// A malformed header is unrecoverable on a byte stream, so it errors.
    pub fn next(&mut self) -> Result<Option<Frame>> {
        if self.buffer.len() < 5 {
            return Ok(None);
        }
        let length = u32::from_be_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]) as usize;
        if length > MAX_FRAME_PAYLOAD {
            return Err(err("frame payload too large"));
        }
        if self.buffer.len() < 5 + length {
            return Ok(None);
        }
        let frame = Frame::decode(self.buffer[0], &self.buffer[5..5 + length])?;
        self.buffer.drain(..5 + length);
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let frames = [
            Frame::Input(b"hello".to_vec()),
            Frame::Resize {
                rows: 40,
                cols: 120,
            },
            Frame::Kill,
            Frame::Output(b"\x1b[2Jworld".to_vec()),
            Frame::Exited(-9),
        ];
        let mut decoder = Decoder::default();
        for frame in &frames {
            decoder.push(&frame.encode());
        }
        for frame in &frames {
            assert_eq!(decoder.next().unwrap().as_ref(), Some(frame));
        }
        assert_eq!(decoder.next().unwrap(), None);
    }

    #[test]
    fn decoder_handles_partial_delivery() {
        let encoded = Frame::Input(b"abcdef".to_vec()).encode();
        let mut decoder = Decoder::default();
        for byte in &encoded[..encoded.len() - 1] {
            decoder.push(std::slice::from_ref(byte));
            assert_eq!(decoder.next().unwrap(), None);
        }
        decoder.push(&encoded[encoded.len() - 1..]);
        assert_eq!(
            decoder.next().unwrap(),
            Some(Frame::Input(b"abcdef".to_vec()))
        );
    }

    #[test]
    fn decoder_rejects_oversized_and_unknown_frames() {
        let mut decoder = Decoder::default();
        let mut oversized = vec![b'I'];
        oversized.extend_from_slice(&((MAX_FRAME_PAYLOAD as u32 + 1).to_be_bytes()));
        decoder.push(&oversized);
        assert!(decoder.next().is_err());

        let mut decoder = Decoder::default();
        decoder.push(&[b'Z', 0, 0, 0, 0]);
        assert!(decoder.next().is_err());

        // Malformed fixed-size payloads are rejected too.
        let mut decoder = Decoder::default();
        decoder.push(&[b'W', 0, 0, 0, 1, 9]);
        assert!(decoder.next().is_err());
    }
}
