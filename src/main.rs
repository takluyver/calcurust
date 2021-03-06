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

mod messaging;
use messaging::{Channel, Message};

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


fn kernel_info(msg: &messaging::Message, sockets: &messaging::KernelSockets) {
    let resp = Message::prepare_reply("kernel_info_reply", &msg, json!({
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
    }));
    sockets.send_msg(resp, Channel::Shell);
}

fn execute(msg: &messaging::Message, sockets: &messaging::KernelSockets, stack: &mut LinkedList<i32>,
            exec_count: &mut u32) {
    if let serde_json::Value::Object(ref contents) = msg.content {
        if let Some(&serde_json::Value::String(ref code)) = contents.get("code") {
            *exec_count = *exec_count + 1;
            calculate(stack, code.clone());
            match stack.front() {
                Some(i) => {
                    let display_msg = Message::prepare_reply("execute_result", msg, json!({
                        "data" : {"text/plain": i.to_string()},
                        "metadata": {},
                        "execution_count": exec_count,
                    }));
                    sockets.send_msg(display_msg, Channel::Iopub);
                    let reply_msg = Message::prepare_reply("execute_reply", msg, json!({
                        "status": "ok",
                        "execution_count": exec_count,
                    }));
                    sockets.send_msg(reply_msg, Channel::Shell);
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


fn dispatch_shell_msg(msg: messaging::Message, sockets: &messaging::KernelSockets, stack: &mut LinkedList<i32>,
                        exec_count: &mut u32) -> bool {
    let mut shutdown = false;
    sockets.send_status("busy", &msg);
    match msg.header.msg_type.as_str() {
        "kernel_info_request" => kernel_info(&msg, sockets),
        "execute_request" => execute(&msg, sockets, stack, exec_count),
        "shutdown_request" => {shutdown = true;},
        _ => println!("Unhandled shell message {}", msg.header.msg_type)
    }
    sockets.send_status("idle", &msg);
    shutdown
}



fn main() {
    //main_cmdline();
    let mut stack: LinkedList<i32> = LinkedList::new();
    let mut exec_count = 0;
    let connect_info = messaging::read_connection_file();
    let sockets = messaging::KernelSockets::new(&connect_info);

    loop {
        let msg = sockets.recv_shell_msg();
        let shutdown = dispatch_shell_msg(msg, &sockets, &mut stack, &mut exec_count);
        if shutdown {
            break;
        }
    }
}
