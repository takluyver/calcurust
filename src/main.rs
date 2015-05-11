use std::io::Write;
use std::collections::LinkedList;
use std::str::FromStr;

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

fn main() {
    let mut stack = LinkedList::new();
    loop {
        let line = input_line("> ").ok().expect("Failed to read stdin");
        if line.starts_with('q') { break; }
        for token in line.trim().split(' ') {
            match token {
                "+" => add(&mut stack),
                "-" => subtract(&mut stack),
                "*" => multiply(&mut stack),
                "/" => divide(&mut stack),
                "" => (),
                _ => match i32::from_str(token) {
                    Ok(i) => stack.push_front(i),
                    Err(_) => panic!("Invalid integer: {}", token)
                }
            }
        }

        match stack.front() {
            Some(i) => println!("= {}", i),
            None => (),
        }
    }
}
