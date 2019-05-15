use std::str;
use std::cmp;
use std::io::BufRead;
use std::str::FromStr;

mod token;

use crate::lexer::token::*;
use crate::lexer::token::Token::Literal;
use core::borrow::BorrowMut;

fn is_register(part: &str) -> Result<Token, ()> {
    let registers = vec![
        "RAX",
        "RBX",
        "RCX",
        "RDX",
        "RBP",
        "RSP",
        "RSI",
        "RDI",
        "EAX",
        "EBX",
        "ECX",
        "EDX",
        "EBP",
        "ESP",
        "ESI",
        "EDI",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14"
    ];

    if registers.contains(&part) {
        Ok(Token::Register(String::from(part)))
    } else {
        Err(())
    }
}

fn parse_token(part: &str) -> Token {
    if let Ok(register) = is_register(part) {
        register
    } else {
        Literal(String::from(part))
    }
}

fn parse_line(line: &str) -> Token {
    let parts: Vec<&str> = line.split_whitespace().collect();

    let mut tokens: Vec<Box<Token>> = Vec::new();

    let mut iter = parts.iter();

    while let Some(part) = iter.next() {
        if part == &"=" {
            return Token::Assignation(
                Box::new(Token::Group(tokens.clone())),
                Box::new(Token::Group(iter.borrow_mut().map(|item| Box::new(parse_token(item))).collect::<Vec<Box<Token>>>()))
            );
        } else {
            tokens.push(Box::new(parse_token(part)));
        }
    }

    Token::Group(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_syscall() {
        assert_eq!(
            Token::Assignation(
                Box::new(Token::Group(vec![
                    Box::new(Token::Register("R9".to_string()))
                ])),
                Box::new(Token::Group(vec![
                    Box::new(Token::Literal("SYSCALL".to_string())),
                    Box::new(Token::Literal("OPEN".to_string()))
                ])),
            ),
            parse_line("R9 = SYSCALL OPEN")
        );
    }
}
