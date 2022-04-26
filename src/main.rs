use std::fs;
mod pcap_struct;
use h1emu_core::soeprotocol::Soeprotocol;
use pcap_struct::Packet;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json::*;

struct ExtractedPacket {
    sender: String,
    data: Vec<u8>,
}

fn convert_payload_to_buff(payload: String) -> Vec<u8> {
    let hex_stream = payload.replace(":", "");
    let decoded = hex::decode(hex_stream).expect("Decoding failed");
    return decoded;
}

fn create_if_doesnt_exist(dir: &str) {
    if !std::fs::metadata(dir).is_err() {
        std::fs::remove_dir_all(dir).unwrap();
    }
    std::fs::create_dir(dir).unwrap();
}

fn main() {
    let contents = fs::read_to_string("C:/Users/Quentin/Desktop/soe-network-parser/examples/z1brlag.json")
        .expect("Something went wrong reading the file");

    const MAX_PACKETS: usize = 0;
    const SERVER_PORT: &str = "20153";
    const USE_CRC: bool = true;
    // use serde to serialize the json
    let packets: Vec<Packet> = serde_json::from_str(&contents).unwrap();
    let mut extracted_packets: Vec<ExtractedPacket> = Vec::new();
    for packet in packets {
        if packet.source.layers.udp.is_some() {
            let udp = packet.source.layers.udp.unwrap();
            if udp.udp_srcport == SERVER_PORT || udp.udp_dstport == SERVER_PORT {
                if packet.source.layers.data.is_some() {
                    let payload = packet.source.layers.data.unwrap().data_data;
                    let buff = convert_payload_to_buff(payload);
                    let sender;
                    if udp.udp_srcport == SERVER_PORT {
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
        if MAX_PACKETS > 0 && extracted_packets.len() >= MAX_PACKETS {
            break;
        }
    }

    // log number of extracted packets
    println!("{} packets extracted", extracted_packets.len());
    // for each extracted packet, write it to a file
    create_if_doesnt_exist("C:/Users/Quentin/Desktop/soe-network-parser/extracted_packets/");
    /*
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
    */
    #[derive(Serialize, Deserialize)]
    struct ExtractedPacketSmall {
        name: String,
    }

    let mut protocol = Soeprotocol::initialize(USE_CRC, 1646082897);
    let mut index: u32 = 0;
    let mut parsed_packets: Vec<Value> = Vec::new();
    for extracted_packet in extracted_packets {
        let parsed_data = protocol.parse(extracted_packet.data);
        parsed_packets.push(json!(parsed_data));
        // use serde to serialize the json with ExtractedPacketSmall
        let extracted_packet_small: ExtractedPacketSmall =
            serde_json::from_str(&parsed_data).unwrap();
        index += 1;
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
}
