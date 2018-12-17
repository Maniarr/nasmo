use std::str;
use std::cmp;

mod token;

#[derive(Debug, PartialEq)]
struct Error {}

fn bytes_is_numeric(input: &[u8]) -> bool {
    for b in input {
        if *b < 47 || *b > 58 {
            return false;
        }
    }

    true
}

fn mov_operand(input: &[u8]) -> Result<token::Instruction, Error> {
    if &input[0..3] == "mov".as_bytes() {
        return Ok(token::Instruction::Mov);
    }

    Err(Error {})
}

// register a, b, c, d
fn volatile_register(input: &[u8]) -> Result<token::Register, Error> {
    let register_names = vec!["a".as_bytes(), "b".as_bytes(), "c".as_bytes(), "d".as_bytes()];

    for name in register_names {
        if input.len() == 2 && &input[..1] == name && input[1] == ('l' as u8) {
            return Ok(token::Register::Register8(str::from_utf8(name).unwrap()));
        } else if input.len() == 2 && &input[..1] == name && input[1] == ('x' as u8) {
            return Ok(token::Register::Register16(str::from_utf8(name).unwrap()));
        }

        if input.len() == 3 && input[0] == ('e' as u8) && &input[1..2] == name && input[2] == ('x' as u8) {
            return Ok(token::Register::Register32(str::from_utf8(name).unwrap()));
        } else if input.len() == 3 && input[0] == ('r' as u8) && &input[1..2] == name && input[2] == ('x' as u8) {
            return Ok(token::Register::Register64(str::from_utf8(name).unwrap()));
        }
    }

    Err(Error {})
}

// register si, di, sp, bp
fn non_volatile_register(input: &[u8]) -> Result<token::Register, Error> {
    let register_names = vec!["si".as_bytes(), "di".as_bytes(), "sp".as_bytes(), "bp".as_bytes()];

    for name in register_names {
        if input.len() == 3 && &input[..2] == name && input[2] == ('l' as u8) {
            return Ok(token::Register::Register8(str::from_utf8(name).unwrap()));
        } else if  input == name {
            return Ok(token::Register::Register16(str::from_utf8(name).unwrap()));
        }

        if input.len() == 3 && input[0] == ('e' as u8) && &input[1..=2] == name {
            return Ok(token::Register::Register32(str::from_utf8(name).unwrap()));
        } else if input.len() == 3 && input[0] == ('r' as u8) && &input[1..=2] == name {
            return Ok(token::Register::Register64(str::from_utf8(name).unwrap()));
        }
    }    

    Err(Error {})
}

fn general_register(input: &[u8]) -> Result<token::Register, Error> {
    let register_names = (8..=15).into_iter().map(|n| n.to_string()).collect::<Vec<String>>();

    for register_name in register_names {
        let name = register_name.as_bytes().clone();

        let (input_name, _) = str::from_utf8(&input[1..]).unwrap().split_at(input.len() - 1);

        if input[0] == 'r' as u8 && input_name.as_bytes() == name {
            if bytes_is_numeric(&input[1..]) {
                return Ok(token::Register::Register64(input_name));
            } else if let Some(c) = input.last() {
                if *c == 'd' as u8 {
                    return Ok(token::Register::Register32(input_name));            
                } else if *c == 'w' as u8 {
                    return Ok(token::Register::Register16(input_name));            
                } else if *c == 'b' as u8 {
                    return Ok(token::Register::Register8(input_name));            
                }
            }
        }
    }

    Err(Error {})
}

fn segment_register(input: &[u8]) -> Result<token::Register, Error>  {
    if input.len() == 2 && &input[1] == &('s' as u8) {
        if &input[0] == &('c' as u8) ||
            &input[0] == &('d' as u8) ||
            &input[0] == &('e' as u8) ||
            &input[0] == &('f' as u8) ||
            &input[0] == &('g' as u8) ||
            &input[0] == &('s' as u8) {
            return Ok(token::Register::SegmentRegister(str::from_utf8(input).unwrap()));
        }
    }

    Err(Error {})
}

fn control_register(input: &[u8]) -> Result<token::Register, Error> {
    if input.len() == 3 && &input[0..2] == "cr".as_bytes()  {
        if bytes_is_numeric(&input[2..]) {
            return Ok(token::Register::ControlRegister(str::from_utf8(&input[2..]).unwrap().parse::<u8>().unwrap()));
        }
    }

    Err(Error {})
}

fn rlags_register(input: &[u8]) -> Result<token::Register, Error> {
    match input == "rflags".as_bytes() {
        true  => Ok(token::Register::RFlagsRegister),
        false => Err(Error {})
    }
}   
