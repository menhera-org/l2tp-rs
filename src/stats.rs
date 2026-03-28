/// Tunnel traffic/error counters.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct TunnelStats {
    /// Transmitted packet count.
    pub tx_packets: u64,
    /// Transmitted byte count.
    pub tx_bytes: u64,
    /// Transmit error count.
    pub tx_errors: u64,
    /// Received packet count.
    pub rx_packets: u64,
    /// Received byte count.
    pub rx_bytes: u64,
    /// Receive error count.
    pub rx_errors: u64,
}

/// Session traffic/error counters.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct SessionStats {
    /// Transmitted packet count.
    pub tx_packets: u64,
    /// Transmitted byte count.
    pub tx_bytes: u64,
    /// Transmit error count.
    pub tx_errors: u64,
    /// Received packet count.
    pub rx_packets: u64,
    /// Received byte count.
    pub rx_bytes: u64,
    /// Receive error count.
    pub rx_errors: u64,
    /// Number of packets discarded due to sequence checks.
    pub rx_seq_discards: u64,
    /// Number of out-of-sequence packets.
    pub rx_oos_packets: u64,
    /// Number of packets discarded due to cookie mismatch.
    pub rx_cookie_discards: u64,
    /// Number of invalid received packets.
    pub rx_invalid: u64,
}
