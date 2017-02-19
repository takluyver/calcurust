#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectInfo {
    ip: String,
    transport: String,
    key: String,
    signature_scheme: String,
    kernel_name: String,
    stdin_port: u16,
    hb_port: u16,
    control_port: u16,
    shell_port: u16,
    iopub_port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MsgHeader {
    msg_id: String,
    username: String,
    pub session: String,
    date: Option<chrono::DateTime<chrono::UTC>>,
    pub msg_type: String,
    version: String,
}
