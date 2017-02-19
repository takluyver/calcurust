extern crate chrono;
extern crate crypto;
extern crate serde_json;
extern crate uuid;
extern crate zmq;

use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::mac::MacResult;
use crypto::sha2::Sha256;
use rustc_serialize::hex::{FromHex,ToHex};
use std::env;
use std::fs::File;
use std::str;
use uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));

pub fn read_connection_file() -> ConnectInfo {
    let path = env::args_os().nth(1).unwrap();
    println!("Connection file: {:?}", path);
    let f = File::open(path).unwrap();
    serde_json::from_reader(f).unwrap()
}

impl MsgHeader {
    pub fn new(msg_type: &str, session: &str) -> MsgHeader {
        MsgHeader {
            msg_id: Uuid::new_v4().hyphenated().to_string(),
            username: "".to_string(),
            session: session.to_owned(),
            date: Some(chrono::UTC::now()),
            msg_type: msg_type.to_owned(),
            version: "5.0".to_owned(),
        }
    }
}

pub struct Message {
    pub identities: Vec<Vec<u8>>,
    pub header: MsgHeader,
    pub parent_header: Option<MsgHeader>,
    pub metadata: serde_json::Value,
    pub content: serde_json::Value,
}

impl Message {
    pub fn prepare_reply(msg_type: &str, parent: &Message, content: serde_json::Value) -> Message {
        Message {
            identities: parent.identities.clone(),
            header: MsgHeader::new(msg_type, &parent.header.session),
            parent_header: Some(parent.header.clone()),
            metadata: json!({}),
            content: content,
        }
    }
}

fn sign_msg_parts(key: &str, msgparts: &[Vec<u8>]) -> MacResult {
    let mut hmac = Hmac::new(Sha256::new(), key.as_bytes());
    for p in msgparts {
        hmac.input(&p);
    }
    hmac.result()
}

pub fn parse_msg(msgparts: Vec<Vec<u8>>, key: &str) -> Message {
    let mut i = msgparts.split(|ref p| p.as_slice() == b"<IDS|MSG>");
    let identities = i.next().unwrap();
    let msgdata = i.next().unwrap();
    assert!(msgdata.len() >= 5);
    // println!("Sig on message: {:?}", str::from_utf8(&msgdata[0]));
    let sb = &str::from_utf8(&msgdata[0]).unwrap().from_hex().unwrap();
    // println!("Binary sig: {:?}", sb);
    let expected_sig = MacResult::new(sb);
    let calculated_sig = sign_msg_parts(key, &msgdata[1..5]);
    // println!("Calculated sig: {:?}", calculated_sig.code());
    // println!("Calculated sig hex: {:?}", calculated_sig.code().to_hex());
    assert!(calculated_sig == expected_sig);
    //println!("Header JSON: {:?}", str::from_utf8(&msgdata[1]).unwrap());
    Message {
        identities: identities.to_owned(),
        header: serde_json::from_slice(&msgdata[1]).unwrap(),
        parent_header: None,
        metadata: serde_json::from_slice(&msgdata[3]).unwrap(),
        content: serde_json::from_slice(&msgdata[4]).unwrap(),
    }
}

pub fn send_msg(msg: Message, socket: &zmq::Socket, key: &str) {
    let mut parts: Vec<zmq::Message> = Vec::new();
    for id in msg.identities {
        parts.push(zmq::Message::from_slice(&id).unwrap());
    }
    parts.push(zmq::Message::from_slice(b"<IDS|MSG>").unwrap());
    let content_parts = vec![
        serde_json::to_vec(&msg.header).unwrap(),
        serde_json::to_vec(&msg.parent_header).unwrap(),
        serde_json::to_vec(&msg.metadata).unwrap(),
        serde_json::to_vec(&msg.content).unwrap()
    ];
    let signature = sign_msg_parts(key, &content_parts);
    let hex_sig = signature.code().to_hex();
    parts.push(zmq::Message::from_slice(hex_sig.as_bytes()).unwrap());
    for part in content_parts {
        parts.push(zmq::Message::from_slice(&part).unwrap());
    }
    
    let (last_part, first_parts) = parts.split_last().unwrap();

    for part in first_parts.iter() {
        socket.send(part, zmq::SNDMORE).unwrap();
    }
    socket.send(last_part, 0).unwrap();
}


pub struct KernelSockets {
    pub shell: zmq::Socket,
    pub control: zmq::Socket,
    pub iopub: zmq::Socket,
    pub hb: zmq:: Socket,
    pub key: String,
}

impl KernelSockets {
    pub fn new(ci: &ConnectInfo) -> KernelSockets {
        assert_eq!(ci.signature_scheme, "hmac-sha256");
        let ctx = zmq::Context::new();
        let inst = KernelSockets {
            shell: ctx.socket(zmq::ROUTER).unwrap(),
            control: ctx.socket(zmq::ROUTER).unwrap(),
            iopub: ctx.socket(zmq::PUB).unwrap(),
            hb: ctx.socket(zmq::REP).unwrap(),
            key: ci.key.to_owned(),
        };
        inst.hb.bind(&make_address(&ci, ci.hb_port)).unwrap();
        inst.iopub.bind(&make_address(&ci, ci.iopub_port)).unwrap();
        inst.control.bind(&make_address(&ci, ci.control_port)).unwrap();
        inst.shell.bind(&make_address(&ci, ci.shell_port)).unwrap();
        inst
    }
    
    pub fn send_status(&self, status: &str, parent_msg: &Message) {
        let msg = Message {
            identities: parent_msg.identities.clone(),
            header: MsgHeader::new("status", &parent_msg.header.session),
            parent_header: Some(parent_msg.header.clone()),
            metadata: json!({}),
            content: json!({"execution_state": status}),
        };
        send_msg(msg, &self.iopub, &self.key);
    }
}

fn make_address(ci: &ConnectInfo, port: u16) -> String {
    ci.transport.clone() + "://" + &ci.ip + ":" + &port.to_string()
}
