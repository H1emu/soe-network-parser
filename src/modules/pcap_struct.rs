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
