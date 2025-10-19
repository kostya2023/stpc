use stpc_encoding;
use stpc_core::StpcError;

#[cfg(test)]
mod tests {
    use stpc_encoding::{TLV};

    use super::*;

    #[test]
    fn encoding() -> Result<(), StpcError> {
        let blocks: Vec<(u8, &[u8])> = vec![
            (1u8, b"Hello!"),
            (2u8, b"From!"),
            (3u8, b"TLVParser!"),
        ];

        let _packed = stpc_encoding::TLVParser::pack(&blocks)?;
        Ok(())
    }

    #[test]
    fn decoding() -> Result<(), StpcError> {
        let blocks: Vec<(u8, &[u8])> = vec![
            (1u8, b"Hello!"),
            (2u8, b"From!"),
            (3u8, b"TLVParser!"),
        ];

        let packed = stpc_encoding::TLVParser::pack(&blocks)?;

        let _unpacked = stpc_encoding::TLVParser::unpack(&packed)?;
        Ok(())
    }
}