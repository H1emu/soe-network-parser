use clap::Parser;
use path_absolutize::*;
use std::env;
use std::fs;
use std::path::Path;

mod lib;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    file_path: String,

    #[clap(short, long, default_value = "1117")]
    server_port: String,

    #[clap(short, long)]
    use_crc: bool,

    #[clap(short, long, default_value_t = 0)]
    crc_seed: u32,

    #[clap(short, long)]
    extract_raw_data: bool,

    #[clap(short, long, default_value_t = 0)]
    max_packets: usize,
}

fn get_absolute_file_path(file_path: &str) -> String {
    let p = Path::new(file_path);
    let cwd = env::current_dir().unwrap();

    return p
        .absolutize_from(&cwd)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
}

pub struct ExtractedPacket {
    pub sender: String,
    pub data: Vec<u8>,
}

fn main() {
    let args = Args::parse();

    let max_packets: usize = args.max_packets;
    let server_port: &str = args.server_port.as_str();
    let use_crc: bool = args.use_crc;
    let extract_raw_data: bool = args.extract_raw_data;
    let file_path = get_absolute_file_path(&args.file_path);
    let crc_seed = args.crc_seed;

    let contents = fs::read_to_string(file_path).expect("Something went wrong reading the file");

    let extracted_packets = lib::pcap_extraction::extract_raw_data_from_pcap(
        contents,
        server_port,
        max_packets,
        extract_raw_data,
    );
    // extract soe packets from extracted packets with extract_soe_packets
    let soe_packets =
        lib::soe_packet_extraction::extract_soe_packets(extracted_packets, use_crc, crc_seed);

    lib::soe_packet_extraction::analyze_soe_packets(soe_packets);
}
