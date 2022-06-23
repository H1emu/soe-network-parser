
    pub fn convert_payload_to_buff(payload: String) -> Vec<u8> {
        let hex_stream = payload.replace(":", "");
        let decoded = hex::decode(hex_stream).expect("Decoding failed");
        return decoded;
    }

    pub fn create_if_doesnt_exist(dir: &str) {
        if !std::fs::metadata(dir).is_err() {
            std::fs::remove_dir_all(dir).unwrap();
        }
        std::fs::create_dir(dir).unwrap();
    }