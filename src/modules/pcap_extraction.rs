
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