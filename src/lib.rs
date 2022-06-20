pub mod pcap_extraction {
    use super::pcap_struct::*;
    use super::utils::*;
    use std::fs;

    pub struct ExtractedPacket {
        pub sender: String,
        pub data: Vec<u8>,
    }

    pub fn extract_raw_data_from_pcap(
        contents: String,
        server_port: &str,
        max_packets: usize,
        extract_raw_data: bool,
    ) -> Vec<ExtractedPacket> {
        // use serde to serialize the json
        let packets: Vec<Packet> = serde_json::from_str(&contents).unwrap();
        let mut extracted_packets: Vec<ExtractedPacket> = Vec::new();
        for packet in packets {
            if packet.source.layers.udp.is_some() {
                let udp = packet.source.layers.udp.unwrap();
                if udp.udp_srcport == server_port || udp.udp_dstport == server_port {
                    if packet.source.layers.data.is_some() {
                        let payload = packet.source.layers.data.unwrap().data_data;
                        let buff = convert_payload_to_buff(payload);
                        let sender;
                        if udp.udp_srcport == server_port {
                            sender = "server"
                        } else {
                            sender = "client"
                        }
                        extracted_packets.push(ExtractedPacket {
                            sender: sender.to_owned(),
                            data: buff,
                        });
                    }
                }
            }
            if max_packets > 0 && extracted_packets.len() >= max_packets {
                break;
            }
        }

        // log number of extracted packets
        println!("{} packets extracted", extracted_packets.len());
        // for each extracted packet, write it to a file
        create_if_doesnt_exist("C:/Users/Quentin/Desktop/soe-network-parser/extracted_packets/");
        if extract_raw_data {
            let mut index: u32 = 0;
            for extracted_packet in &extracted_packets {
                index += 1;
                let mut file_name: String =
                    "C:/Users/Quentin/Desktop/soe-network-parser/extracted_packets/".to_owned();
                file_name.push_str(&index.to_string());
                file_name.push_str("-");
                file_name.push_str(&extracted_packet.sender);
                file_name.push_str(".bin");
                fs::write(file_name, &extracted_packet.data).expect("Unable to write to file");
            }
        }
        return extracted_packets;
    }
}

pub mod soe_packet_extraction {
    use super::pcap_extraction::*;
    use h1emu_core::soeprotocol::Soeprotocol;
    use h1emu_core::soeprotocol_packets_structs::AckPacket;
    use h1emu_core::soeprotocol_packets_structs::SubBasePackets;
    use serde_derive::Deserialize;
    use serde_derive::Serialize;
    use serde_json::*;
    use std::fs;

    #[derive(Serialize, Deserialize)]
    struct ExtractedPacketSmall {
        name: String,
    }

    pub fn extract_soe_packets(
        extracted_packets: Vec<ExtractedPacket>,
        use_crc: bool,
        crc_seed: u32,
    ) -> Vec<Value> {
        let mut protocol = Soeprotocol::initialize(use_crc, crc_seed);
        let mut index: u32 = 0;
        let mut parsed_packets: Vec<Value> = Vec::new();
        let mut parsed_server_packets: Vec<Value> = Vec::new();
        for extracted_packet in extracted_packets {
            let parsed_data = protocol.parse(extracted_packet.data);
            parsed_packets.push(json!(parsed_data));
            // use serde to serialize the json with ExtractedPacketSmall
            let extracted_packet_small: ExtractedPacketSmall =
                serde_json::from_str(&parsed_data).unwrap();
            index += 1;
            if extracted_packet.sender == "server" {
                parsed_server_packets.push(json!(parsed_data));
            }
            let mut file_name: String =
                "C:/Users/Quentin/Desktop/soe-network-parser/extracted_packets/".to_owned();
            file_name.push_str(&index.to_string());
            file_name.push_str("-");
            file_name.push_str(&extracted_packet.sender);
            file_name.push_str("-");
            file_name.push_str(extracted_packet_small.name.as_str());
            file_name.push_str(".json");
            fs::write(file_name, parsed_data).expect("Unable to write to file");
        }
        fs::write(
            "C:/Users/Quentin/Desktop/soe-network-parser/extracted_packets/0-full.json".to_owned(),
            serde_json::to_string_pretty(&parsed_packets).unwrap(),
        )
        .expect("Unable to write to file");
        return parsed_server_packets;
    }

    fn contain_multiple_acks(packet: &SubBasePackets) -> bool {
        // count the number of packets named "Ack" inside the MultiPacket
        let mut ack_count: u32 = 0;
        for packet_part in &packet.sub_packets {
            if packet_part.name == "Ack" {
                ack_count += 1;
            }
        }
        return ack_count > 1;
    }
    pub fn analyze_soe_packets(parsed_packets: Vec<Value>) {
        let mut multiple_acks_per_buffer: u32 = 0;
        let mut total_multi_packets: u32 = 0;
        let mut total_acks: u32 = 0;
        let mut useless_acks: u32 = 0;
        let mut useless_outoforder: u32 = 0;
        let mut total_outoforder: u32 = 0;
        let mut last_ack: u16 = 0;
        for parsed_packet in parsed_packets {
            let extracted_packet_small: ExtractedPacketSmall =
                serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
            match extracted_packet_small.name.as_str() {
                "MultiPacket" => {
                    total_multi_packets += 1;
                    let packet: SubBasePackets =
                        serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
                    if contain_multiple_acks(&packet) {
                        multiple_acks_per_buffer += 1;
                    }
                    for packet_part in packet.sub_packets {
                        if packet_part.name == "Ack" {
                            total_acks += 1;
                            if packet_part.sequence.unwrap() < last_ack {
                                useless_acks += 1;
                            } else {
                                last_ack = packet_part.sequence.unwrap();
                            }
                        } else if packet_part.name == "OutOfOrder" {
                            total_outoforder += 1;
                            if packet_part.sequence.unwrap() < last_ack {
                                useless_outoforder += 1;
                            }
                        }
                    }
                }
                "Ack" => {
                    total_acks += 1;
                    let packet: AckPacket =
                        serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
                    if packet.sequence < last_ack {
                        useless_acks += 1;
                    }
                    last_ack = packet.sequence;
                }
                "OutOfOrder" => {
                    total_outoforder += 1;
                    let packet: AckPacket =
                        serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
                    if packet.sequence < last_ack {
                        useless_outoforder += 1;
                    }
                }
                _ => {

                }
            }
        }
        if total_multi_packets > 0 {
            // Log the pourcentage of multiple acks per buffer
            println!(
                "{}% of multiple acks per buffer",
                (multiple_acks_per_buffer * 100) / total_multi_packets
            );
        }
        if total_acks > 0 {
            // Log the pourcentage of useless acks
            println!("{}% of useless acks", (useless_acks * 100) / total_acks);
        }
        if total_outoforder > 0 {
            // Log the pourcentage of useless outoforder
            println!(
                "{}% of useless outoforder",
                (useless_outoforder * 100) / total_outoforder
            );
        }
    }
}

pub mod pcap_struct {
    use serde_derive::Deserialize;
    use serde_derive::Serialize;
    use serde_json::Value;
    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Packet {
        #[serde(rename = "_index")]
        pub index: String,
        #[serde(rename = "_type")]
        pub type_field: String,
        #[serde(rename = "_score")]
        pub score: Value,
        #[serde(rename = "_source")]
        pub source: Source,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Source {
        pub layers: Layers,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Layers {
        pub raw: String,
        pub udp: Option<Udp>,
        pub data: Option<Data>,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct IpDsfieldTree {
        #[serde(rename = "ip.dsfield.dscp")]
        pub ip_dsfield_dscp: String,
        #[serde(rename = "ip.dsfield.ecn")]
        pub ip_dsfield_ecn: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct IpFlagsTree {
        #[serde(rename = "ip.flags.rb")]
        pub ip_flags_rb: String,
        #[serde(rename = "ip.flags.df")]
        pub ip_flags_df: String,
        #[serde(rename = "ip.flags.mf")]
        pub ip_flags_mf: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Udp {
        #[serde(rename = "udp.srcport")]
        pub udp_srcport: String,
        #[serde(rename = "udp.dstport")]
        pub udp_dstport: String,
        #[serde(rename = "udp.length")]
        pub udp_length: String,
        #[serde(rename = "udp.checksum")]
        pub udp_checksum: String,
        #[serde(rename = "udp.checksum.status")]
        pub udp_checksum_status: String,
        #[serde(rename = "udp.stream")]
        pub udp_stream: String,
        #[serde(rename = "Timestamps")]
        pub timestamps: Timestamps,
        #[serde(rename = "udp.payload")]
        pub udp_payload: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Timestamps {
        #[serde(rename = "udp.time_relative")]
        pub udp_time_relative: String,
        #[serde(rename = "udp.time_delta")]
        pub udp_time_delta: String,
    }

    #[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Data {
        #[serde(rename = "data.data")]
        pub data_data: String,
        #[serde(rename = "data.len")]
        pub data_len: String,
    }
}

pub mod utils {
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
}
