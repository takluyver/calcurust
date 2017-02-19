use std::env;
use std::fs::File;
use std::io::Write;
use std::collections::LinkedList;
use std::str;

extern crate zmq;
#[macro_use]
extern crate serde_json;
extern crate crypto;
extern crate rustc_serialize;
extern crate uuid;
extern crate chrono;

use rustc_serialize::hex::{FromHex,ToHex};
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::mac::MacResult;
use crypto::sha2::Sha256;
use uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));

fn input_line(prompt: &str) -> Result<String, std::io::Error> {
    let mut stdout = std::io::stdout();
    let mut line = String::new();
    try!(stdout.write(prompt.as_bytes()));
    try!(stdout.flush());
    try!(std::io::stdin().read_line(&mut line));
    return Ok(line);
}

fn add(stack: &mut LinkedList<i32>) {
    let n1 = stack.pop_front().unwrap();
    let n2 = stack.pop_front().unwrap();
    stack.push_front(n1 + n2);
}

fn subtract(stack: &mut LinkedList<i32>) {
    let n1 = stack.pop_front().unwrap();
    let n2 = stack.pop_front().unwrap();
    stack.push_front(n2 - n1);
}

fn multiply(stack: &mut LinkedList<i32>) {
    let n1 = stack.pop_front().unwrap();
    let n2 = stack.pop_front().unwrap();
    stack.push_front(n1 * n2);
}

fn divide(stack: &mut LinkedList<i32>) {
    let n1 = stack.pop_front().unwrap();
    let n2 = stack.pop_front().unwrap();
    stack.push_front(n2 / n1);
}

fn calculate(stack: &mut LinkedList<i32>, line: String) {
    for token in line.trim().split(' ') {
        match token {
            "+" => add(stack),
            "-" => subtract(stack),
            "*" => multiply(stack),
            "/" => divide(stack),
            "" => (),
            _ => match token.parse::<i32>() {
                Ok(i) => stack.push_front(i),
                Err(_) => {
                    println!("Invalid integer: {}", token);
                    break;
                }
            }
        }
    }
}

fn main_cmdline() {
    let mut stack = LinkedList::new();
    loop {
        let line = input_line("> ").ok().expect("Failed to read stdin");
        if line.starts_with('q') { break; }
        calculate(&mut stack, line);

        match stack.front() {
            Some(i) => println!("= {}", i),
            None => (),
        }
    }
}



fn read_connection_file() -> ConnectInfo {
    let path = env::args_os().nth(1).unwrap();
    println!("Connection file: {:?}", path);
    let f = File::open(path).unwrap();
    serde_json::from_reader(f).unwrap()
}

fn make_address(ci: &ConnectInfo, port: u16) -> String {
    ci.transport.clone() + "://" + &ci.ip + ":" + &port.to_string()
}

struct Message {
    identities: Vec<Vec<u8>>,
    header: MsgHeader,
    parent_header: Option<MsgHeader>,
    metadata: serde_json::Value,
    content: serde_json::Value,
}

impl MsgHeader {
    fn new(msg_type: &str, session: &str) -> MsgHeader {
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

fn sign_msg_parts(key: &str, msgparts: &[Vec<u8>]) -> MacResult {
    let mut hmac = Hmac::new(Sha256::new(), key.as_bytes());
    for p in msgparts {
        hmac.input(&p);
    }
    hmac.result()
}

fn parse_msg(msgparts: Vec<Vec<u8>>, key: &str) -> Message {
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

fn send_msg(msg: Message, socket: &zmq::Socket, key: &str) {
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

fn kernel_info(msg: &Message, sockets: &KernelSockets) {
    let info = json!({
        "protocol_version": "5.0",
        "implementation": "calcurust",
        "implementation_version": "0.1",
        "language_info": {
            "name": "RPN",
            "version": "0.1",
            "mimetype": "text/plain",
            "file_extension": ".txt",
        },
        "banner": "Reverse polish notation calculator",
    });
    let resp = Message {
        identities: msg.identities.clone(),
        header: MsgHeader::new("kernel_info_reply", &msg.header.session),
        parent_header: Some(msg.header.clone()),
        metadata: json!({}),
        content: info,
    };
    send_msg(resp, &sockets.shell, &sockets.key);
}

fn execute(msg: &Message, sockets: &KernelSockets, stack: &mut LinkedList<i32>,
            exec_count: &mut u32) {
    if let serde_json::Value::Object(ref contents) = msg.content {
        if let Some(&serde_json::Value::String(ref code)) = contents.get("code") {
            *exec_count = *exec_count + 1;
            calculate(stack, code.clone());
            match stack.front() {
                Some(i) => {
                    let display_content = json!({
                        "data" : {"text/plain": i.to_string()},
                        "metadata": {},
                        "execution_count": exec_count,
                    });
                    let display_msg = Message{
                        identities: msg.identities.clone(),
                        header: MsgHeader::new("execute_result", &msg.header.session),
                        parent_header: Some(msg.header.clone()),
                        metadata: json!({}),
                        content: display_content,
                    };
                    send_msg(display_msg, &sockets.iopub, &sockets.key);
                    let reply_content = json!({
                        "status": "ok",
                        "execution_count": exec_count,
                    });
                    let reply_msg = Message {
                        identities: msg.identities.clone(),
                        header: MsgHeader::new("execute_reply", &msg.header.session),
                        parent_header: Some(msg.header.clone()),
                        metadata: json!({}),
                        content: reply_content,
                    };
                    send_msg(reply_msg, &sockets.shell, &sockets.key);
                },
                None => (),
            }
        } else {
            println!("Failed to get code");
        }
    } else {
        println!("Failed to get contents");
    }
}

fn send_status(status: &str, parent_msg: &Message, sockets: &KernelSockets) {
    let msg = Message {
        identities: parent_msg.identities.clone(),
        header: MsgHeader::new("status", &parent_msg.header.session),
        parent_header: Some(parent_msg.header.clone()),
        metadata: json!({}),
        content: json!({"execution_state": status}),
    };
    send_msg(msg, &sockets.iopub, &sockets.key);
}

fn dispatch_shell_msg(msg: Message, sockets: &KernelSockets, stack: &mut LinkedList<i32>,
                        exec_count: &mut u32) -> bool {
    let mut shutdown = false;
    send_status("busy", &msg, sockets);
    match msg.header.msg_type.as_str() {
        "kernel_info_request" => kernel_info(&msg, sockets),
        "execute_request" => execute(&msg, sockets, stack, exec_count),
        "shutdown_request" => {shutdown = true;},
        _ => println!("Unhandled shell message {}", msg.header.msg_type)
    }
    send_status("idle", &msg, sockets);
    shutdown
}

struct KernelSockets {
    shell: zmq::Socket,
    control: zmq::Socket,
    iopub: zmq::Socket,
    hb: zmq:: Socket,
    key: String,
}

impl KernelSockets {
    fn new(key: &str) -> KernelSockets {
        let ctx = zmq::Context::new();
        KernelSockets {
            shell: ctx.socket(zmq::ROUTER).unwrap(),
            control: ctx.socket(zmq::ROUTER).unwrap(),
            iopub: ctx.socket(zmq::PUB).unwrap(),
            hb: ctx.socket(zmq::REP).unwrap(),
            key: key.to_owned(),
        }
    }
}

fn main() {
    //main_cmdline();
    let mut stack: LinkedList<i32> = LinkedList::new();
    let mut exec_count = 0;
    let connect_info = read_connection_file();
    println!("Shell port: {}", connect_info.shell_port);
    assert_eq!(connect_info.signature_scheme, "hmac-sha256");
    let sockets = KernelSockets::new(&connect_info.key);
    sockets.hb.bind(&make_address(&connect_info, connect_info.hb_port)).unwrap();
    sockets.iopub.bind(&make_address(&connect_info, connect_info.iopub_port)).unwrap();
    sockets.control.bind(&make_address(&connect_info, connect_info.control_port)).unwrap();
    sockets.shell.bind(&make_address(&connect_info, connect_info.shell_port)).unwrap();
    
    //send_status("idle", sockets, )
    
    let mut poll_items = [
        sockets.shell.as_poll_item(zmq::POLLIN),
        sockets.control.as_poll_item(zmq::POLLIN),
        sockets.hb.as_poll_item(zmq::POLLIN),
    ];
    loop {
        zmq::poll(&mut poll_items, -1).unwrap();
        let mut shutdown = false;
        if poll_items[0].is_readable() {
            let rawmsg = sockets.shell.recv_multipart(0).unwrap();
            let msg = parse_msg(rawmsg, &connect_info.key);
            shutdown = dispatch_shell_msg(msg, &sockets, &mut stack, &mut exec_count);
        }
        if poll_items[1].is_readable() {
            let rawmsg = sockets.control.recv_multipart(0).unwrap();
            let msg = parse_msg(rawmsg, &connect_info.key);
            shutdown = dispatch_shell_msg(msg, &sockets, &mut stack, &mut exec_count);
        }
        if poll_items[2].is_readable() {
            let hbmsg = sockets.hb.recv_bytes(0).unwrap();
            sockets.hb.send(&hbmsg, 0).unwrap();
        }
        if shutdown {
            break;
        }
    }
}
