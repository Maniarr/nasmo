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

fn general_register(input: &[u8]) -> Result<token::Register, Error> {
    if &input[0] == &('r' as u8) && bytes_is_numeric(&input[1..]) {
        return Ok(token::Register::GeneralRegister(str::from_utf8(&input[1..]).unwrap().parse::<u8>().unwrap()));
    }

    if input.len() == 2 && (&input[0] == &('a' as u8) || 
                            &input[0] == &('b' as u8) || 
                            &input[0] == &('c' as u8) || 
                            &input[0] == &('d' as u8)) {
        if &input[1] == &('l' as u8) {
            return Ok(token::Register::GeneralRegister8L(input[0].clone() as char));
        } else if &input[1] == &('h' as u8) {
            return Ok(token::Register::GeneralRegister8H(input[0].clone() as char));
        } else if &input[1] == &('x' as u8) {
            return Ok(token::Register::GeneralRegister16(input[0].clone() as char));
        }
    }

    if input.len() == 3 && (&input[1] == &('a' as u8) || 
                            &input[1] == &('b' as u8) || 
                            &input[1] == &('c' as u8) || 
                            &input[1] == &('d' as u8)) {
        if &input[0] == &('e' as u8) && &input[2] == &('x' as u8) {
            return Ok(token::Register::GeneralRegister32(input[1].clone() as char));
        } else if &input[0] == &('r' as u8) && &input[2] == &('x' as u8) {
            return Ok(token::Register::GeneralRegister64(input[1].clone() as char));
        }
    }

    Err(Error {})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rax_register() {
        assert_eq!(Ok(token::Register::GeneralRegister64('a')), general_register(&"rax".as_bytes()));
    }
}
