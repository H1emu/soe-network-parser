use super::pcap_extraction::*;
use h1emu_core::soeprotocol::Soeprotocol;
use h1emu_core::soeprotocol_packets_structs::{AckPacket, DataPacket, SubBasePackets};
use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json::*;
use std::collections::HashMap;
use std::fs;

#[derive(Serialize, Deserialize)]
struct ExtractedPacketSmall {
    name: String,
}

pub fn extract_soe_packets(
    extracted_packets: Vec<ExtractedPacket>,
    output_directory: &String,
    use_crc: bool,
    crc_seed: u32,
    write_packets_to_files: bool,
    max_packets: usize,
) -> HashMap<String, Vec<Value>> {
    let mut protocol = Soeprotocol::initialize(use_crc, crc_seed);
    let mut index: u32 = 0;
    let mut parsed_packets: Vec<Value> = Vec::new();
    let mut parsed_server_packets: Vec<Value> = Vec::new();
    let mut parsed_client_packets: Vec<Value> = Vec::new();
    let mut parsed_packets_map: HashMap<String, Vec<Value>> = HashMap::new();

    for extracted_packet in extracted_packets {
        let parsed_data = protocol.parse(extracted_packet.data);
        parsed_packets.push(json!(parsed_data));
        // use serde to serialize the json with ExtractedPacketSmall
        let extracted_packet_small: ExtractedPacketSmall =
            serde_json::from_str(&parsed_data).unwrap();
        index += 1;
        if extracted_packet.sender == "server" {
            parsed_server_packets.push(json!(parsed_data));
        } else {
            parsed_client_packets.push(json!(parsed_data));
        }
        if write_packets_to_files {
            let mut file_name: String = output_directory.to_owned();
            file_name.push_str(&index.to_string());
            file_name.push_str("-");
            file_name.push_str(&extracted_packet.sender);
            file_name.push_str("-");
            file_name.push_str(extracted_packet_small.name.as_str());
            file_name.push_str(".json");
            fs::write(file_name, parsed_data).expect("Unable to write to file");
        }
        if max_packets > 0 && index as usize >= max_packets {
            break;
        }
    }
    if write_packets_to_files {
        let mut file_name: String = output_directory.to_owned();
        file_name.push_str("0-full.json");
        fs::write(
            file_name,
            serde_json::to_string_pretty(&parsed_packets).unwrap(),
        )
        .expect("Unable to write to file");
    }
    parsed_packets_map.insert("client".to_owned(), parsed_client_packets);
    parsed_packets_map.insert("server".to_owned(), parsed_server_packets);
    return parsed_packets_map;
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

struct Stats {
    multiple_acks_per_buffer: u32,
    total_multi_packets: u32,
    total_acks: u32,
    useless_acks: u32,
    useless_outoforder: u32,
    total_outoforder: u32,
    last_ack: u16,
    last_sequence: HashMap<u16, bool>,
    resended_data: u32,
    total_data_packets: u32,
}
fn analyse_packets(parsed_packets: &Vec<Value>, stats: &mut Stats) -> () {
    for parsed_packet in parsed_packets {
        let extracted_packet_small: ExtractedPacketSmall =
            serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
        match extracted_packet_small.name.as_str() {
            "MultiPacket" => {
                stats.total_multi_packets += 1;
                let packet: SubBasePackets =
                    serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
                if contain_multiple_acks(&packet) {
                    stats.multiple_acks_per_buffer += 1;
                }
                for packet_part in packet.sub_packets {
                    if packet_part.name == "Ack" {
                        stats.total_acks += 1;
                        if packet_part.sequence.unwrap() < stats.last_ack {
                            stats.useless_acks += 1;
                        } else {
                            stats.last_ack = packet_part.sequence.unwrap();
                        }
                    } else if packet_part.name == "OutOfOrder" {
                        stats.total_outoforder += 1;
                        if packet_part.sequence.unwrap() < stats.last_ack {
                            stats.useless_outoforder += 1;
                        }
                    }
                }
            }
            "Ack" => {
                stats.total_acks += 1;
                let packet: AckPacket =
                    serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
                if packet.sequence < stats.last_ack {
                    stats.useless_acks += 1;
                }
                stats.last_ack = packet.sequence;
            }
            "OutOfOrder" => {
                stats.total_outoforder += 1;
                let packet: AckPacket =
                    serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
                if packet.sequence < stats.last_ack {
                    stats.useless_outoforder += 1;
                }
            }
            "Data" => {
                let packet: DataPacket =
                    serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
                if stats.last_sequence.contains_key(&packet.sequence) {
                    stats.resended_data += 1;
                } else {
                    stats.last_sequence.insert(packet.sequence, true);
                }
                stats.total_data_packets += 1;
            }
            "DataFragment" => {
                let packet: DataPacket =
                    serde_json::from_str(&parsed_packet.as_str().unwrap()).unwrap();
                if stats.last_sequence.contains_key(&packet.sequence) {
                    stats.resended_data += 1;
                } else {
                    stats.last_sequence.insert(packet.sequence, true);
                }
                stats.total_data_packets += 1;
            }
            _ => {}
        }
    }
}

fn log_stats(stats: Stats) -> () {
    if stats.total_multi_packets > 0 {
        // Log the pourcentage of multiple acks per buffer
        println!(
            "{}% of multiple acks per buffer",
            (stats.multiple_acks_per_buffer * 100) as f32 / stats.total_multi_packets as f32
        );
    }
    if stats.total_acks > 0 {
        // Log the pourcentage of useless acks
        println!(
            "{}% of useless acks",
            (stats.useless_acks * 100) as f32 / stats.total_acks as f32
        );
    }
    if stats.total_outoforder > 0 {
        // Log the pourcentage of useless outoforder
        println!(
            "{}% of useless outoforder",
            (stats.useless_outoforder * 100) as f32 / stats.total_outoforder as f32
        );
    }
    if stats.total_data_packets > 0 {
        // Log the pourcentage of resended data from client
        println!(
            "{}% of resended data",
            ((stats.resended_data + 1) * 100) as f32 / stats.total_data_packets as f32
        );
    }
}
pub fn analyze_soe_packets(parsed_packets: HashMap<String, Vec<Value>>) {
    let server_packets = parsed_packets.get("server").unwrap();

    let mut server_stats = Stats {
        multiple_acks_per_buffer: 0,
        total_multi_packets: 0,
        total_acks: 0,
        useless_acks: 0,
        useless_outoforder: 0,
        total_outoforder: 0,
        last_ack: 0,
        last_sequence: HashMap::new(),
        resended_data: 0,
        total_data_packets: 0,
    };
    analyse_packets(server_packets, &mut server_stats);

    println!("server packets stats");

    log_stats(server_stats);

    let client_packets = parsed_packets.get("client").unwrap();

    let mut client_stats = Stats {
        multiple_acks_per_buffer: 0,
        total_multi_packets: 0,
        total_acks: 0,
        useless_acks: 0,
        useless_outoforder: 0,
        total_outoforder: 0,
        last_ack: 0,
        last_sequence: HashMap::new(),
        resended_data: 0,
        total_data_packets: 0,
    };
    analyse_packets(client_packets, &mut client_stats);

    println!("client packets stats");

    log_stats(client_stats);
}
