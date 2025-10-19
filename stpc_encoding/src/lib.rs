use std::convert::TryInto;
use stpc_core::StpcError;



pub trait TLV {
    fn pack(blocks: &[(u8, &[u8])]) -> Result<Vec<u8>, StpcError>;
    fn unpack(message: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, StpcError>;
}


#[derive(Debug)]
pub struct TLVParser {}


impl TLV for TLVParser {
    fn pack(blocks: &[(u8, &[u8])]) -> Result<Vec<u8>, StpcError> {
        let mut packet = Vec::new();

        for (tag, data) in blocks {
            packet.push(*tag);
            let len = data.len() as u32;
            packet.extend(&len.to_be_bytes());
            packet.extend(*data);
        }

        let total_len = packet.len() as u64;
        let mut result = total_len.to_be_bytes().to_vec();
        result.extend(packet);

        Ok(result)
    }

    fn unpack(message: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, StpcError> {
        if message.len() < 8 {
            return Err(StpcError::InvalidPacketError(format!("Message must be greater than 8 bytes, received: {}", message.len())));
        }

        let total_len = u64::from_be_bytes(message[0..8].try_into().unwrap()) as usize;
        if message.len() - 8 < total_len {
            return Err(StpcError::InvalidPacketError(format!("Message must be greater than 8 bytes, received: {}", message.len())));
        }

        let payload = &message[8..8 + total_len];
        let mut offset = 0;
        let mut blocks = Vec::new();

        while offset < payload.len() {
            if offset + 5 > payload.len() {
                return Err(StpcError::InvalidPacketError(format!("Block must be greater than 5 bytes, received: {}", message.len())));
            }

            let tag = payload[offset];
            let length = u32::from_be_bytes(payload[offset + 1..offset + 5].try_into().unwrap()) as usize;
            offset += 5;

            if offset + length > payload.len() {
                return Err(StpcError::InvalidPacketError(format!("Block at offset {} claims length {}, but only {} bytes remain", offset, length, payload.len() - offset)));         }

            blocks.push((tag, payload[offset..offset + length].to_vec()));
            offset += length;
        }

        Ok(blocks)
    }

}