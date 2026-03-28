#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_errors: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_errors: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_errors: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_errors: u64,
    pub rx_seq_discards: u64,
    pub rx_oos_packets: u64,
    pub rx_cookie_discards: u64,
    pub rx_invalid: u64,
}
