use crate::lexer::token::{Token, Instruction};
use std::ops::Deref;
use core::borrow::{Borrow, BorrowMut};
use std::str::FromStr;

fn get_syscall_info<'a>(syscall_name: &'a str) -> Result<(String, usize), ()> {
    match syscall_name {
        "EXIT"      => Ok(("60".to_string(), 1)),
        "EXECVE"    => Ok(("59".to_string(), 3)),
        "CONNECT"   => Ok(("42".to_string(), 3)),
        "SOCKET"    => Ok(("41".to_string(), 3)),
        "DUP2"      => Ok(("33".to_string(), 2)),
        _ => Err(())
    }
}

fn inet_addr<'a>(ip: &'a str) -> Option<u32> {
    let mut result = 0;
    let parts = ip.split(".").collect::<Vec<&str>>();

    if parts.len() != 4 {
        return None;
    }

    for (i, item) in parts.iter().enumerate() {
        if let Ok(byte) = u32::from_str(item) {
            result += byte << 8 * (3 - i);
        } else {
            return None
        }
    }

    Some(result)
}

fn reverse_hex(hex: String) -> String {
    let mut v = Vec::new();

    let mut hex = hex.as_str();

    while !hex.is_empty() {
        let (rest, chunk) = hex.split_at(hex.len() - 2);
        v.push(chunk);
        hex = rest;
    }

    v.iter().map(|item| item.to_string()).collect::<String>()
}

pub fn assemble_syscall(token_syscall: Box<Token>) -> Result<Vec<Instruction> , ()> {
    let registers = ["rdi", "rsi", "rdx", "r10", "r8", "r9"];

    if let Token::Syscall(syscall_name, parameters) = Box::leak(token_syscall) {
        let (syscall_number, syscall_nb_params) = get_syscall_info(&syscall_name)?;

        let mut tokens = vec![
            Instruction {
                mnemonic: "mov".to_string(),
                operands: vec!["rax".to_string(), syscall_number],
                used_registers: vec!["rax".to_string()],
                result_register: "rax".to_string()
            }
        ];

        if parameters.len() == syscall_nb_params && parameters.len() <= 6 {
            for (i, item) in parameters.iter().enumerate() {
                let used_register = registers[i];

                match item.deref().clone() {
                    Token::Literal(mut param) => {
                        if param.contains("{") && param.contains("}") {
                            param.pop();

                            let parts = param.split("{").collect::<Vec<&str>>();


                            match parts.get(0) {
                                Some(&"sockaddr_in") => {
                                    if let Some(parameters) = parts.get(1) {
                                        let parts = parameters.split(",").collect::<Vec<&str>>();

                                        if let (Some(ip_str), Some(port_str), Some(family_str)) = (parts.get(0), parts.get(1), parts.get(2) ) {
                                            if let Some(ip) = inet_addr(ip_str) {
                                                if let Ok(port) = u16::from_str(port_str) {
                                                    if let Ok(family) = u16::from_str(family_str) {
                                                        let addr_struct = format!("qword 0x{}{}{:04x}", reverse_hex(format!("{:08x}", ip)), reverse_hex(format!("{:04x}", port)), family);

                                                        tokens.push(
                                                            Instruction {
                                                                mnemonic: "push".to_string(),
                                                                operands: vec![format!("qword 0x{:016x}", 0)],
                                                                used_registers: vec![],
                                                                result_register: "rsp".to_string()
                                                            }
                                                        );

                                                        tokens.push(
                                                            Instruction {
                                                                mnemonic: "push".to_string(),
                                                                operands: vec![addr_struct],
                                                                used_registers: vec![],
                                                                result_register: "rsp".to_string()
                                                            }
                                                        );

                                                        tokens.push(
                                                            Instruction {
                                                                mnemonic: "mov".to_string(),
                                                                operands: vec![used_register.to_string(), "rsp".to_string()],
                                                                used_registers: vec![used_register.to_string(), "rsp".to_string()],
                                                                result_register: used_register.to_string()
                                                            }
                                                        );
                                                    }
                                                }
                                            }

                                        };
                                    }
                                },
                                _ => {}
                            };

                        } else if param.starts_with("\"") && param.ends_with("\"") {
                            let mut hex_string = String::from("00");

                            param.remove(0);
                            param.pop();

                            if (param.len() + 1) % 8 < 8 {
                                for _ in 0..8 - ((param.len() + 1) % 8) {
                                    hex_string.push_str("00");
                                }
                            }

                            while let Some(c) = param.pop() {
                                hex_string.push_str(&format!("{:02x}", c as i8));

                                if hex_string.len() == 16 {
                                    tokens.push(
                                        Instruction {
                                            mnemonic: "push".to_string(),
                                            operands: vec![format!("qword 0x{}", hex_string.clone())],
                                            used_registers: vec![],
                                            result_register: "rsp".to_string()
                                        }
                                    );

                                    hex_string.clear();
                                }
                            }

                            if hex_string.len() > 0 {
                                tokens.push(
                                    Instruction {
                                        mnemonic: "push".to_string(),
                                        operands: vec![format!("qword 0x{}", hex_string.clone())],
                                        used_registers: vec![],
                                        result_register: "rsp".to_string()
                                    }
                                );
                            }

                            tokens.push(
                                Instruction {
                                    mnemonic: "mov".to_string(),
                                    operands: vec![used_register.to_string(), "rsp".to_string()],
                                    used_registers: vec![used_register.to_string(), "rsp".to_string()],
                                    result_register: used_register.to_string()
                                }
                            );
                        } else {
                            tokens.push(
                                Instruction {
                                    mnemonic: "mov".to_string(),
                                    operands: vec![used_register.to_string(), param.to_string()],
                                    used_registers: vec![used_register.to_string()],
                                    result_register: used_register.to_string()
                                }
                            );
                        }
                    },
                    Token::Register(register) => {
                        tokens.push(
                            Instruction {
                                mnemonic: "mov".to_string(),
                                operands: vec![used_register.to_string(), register.to_lowercase().to_string()],
                                used_registers: vec![used_register.to_string(), register.to_string()],
                                result_register: used_register.to_string()
                            }
                        );
                    },
                    _ => return Err(())
                };
            }

            tokens.push(Instruction {
                mnemonic: "syscall".to_string(),
                operands: vec![],
                used_registers: registers[..syscall_nb_params].iter().map(|item| item.to_string()).collect(),
                result_register: "rax".to_string()
            });

            return Ok(tokens);
        }
    }

    Err(())
}

pub fn assemble_assignation(token_assignation: Box<Token>) -> Result<Vec<Instruction> , ()> {
    let mut tokens = Vec::new();

    if let Token::Assignation(destination_token, source_tokens) = *token_assignation {
        tokens.append(&mut assemble_syscall(source_tokens.clone())?);

        if let Some(instruction) = tokens.last().clone() {
            let result_register = instruction.result_register.to_string();

            if let Token::Register(register_name) = *destination_token.clone() {
                tokens.push(Instruction {
                    mnemonic: "mov".to_string(),
                    operands: vec![register_name.to_lowercase().clone(), result_register.clone()],
                    used_registers: vec![register_name.clone(), result_register],
                    result_register: register_name
                });
            }
        } else {
            return Err(());
        }
    } else {
        return Err(());
    }

    return Ok(tokens);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_syscall() {
        /*dbg!(assemble_syscall(Box::new(
            Token::Syscall("SOCKET".to_string(), vec![
                Box::new(Token::Literal("2".to_string())),
                Box::new(Token::Literal("1".to_string())),
                Box::new(Token::Literal("6".to_string()))
            ])
        )));*/
    }

    #[test]
    fn test_assemble_assignation() {
        /*dbg!(assemble_assignation(Box::new(
            Token::Assignation(
                Box::new(Token::Register("R9".to_string())),
                Box::new(
                    Token::Syscall("SOCKET".to_string(), vec![
                        Box::new(Token::Literal("2".to_string())),
                        Box::new(Token::Literal("1".to_string())),
                        Box::new(Token::Literal("6".to_string()))
                    ])
                )
            )
        )));*/
    }

    #[test]
    fn test_assemble_syscall_parameter() {
        /*dbg!(assemble_syscall(Box::new(
            Token::Syscall("EXECVE".to_string(), vec![
                Box::new(Token::Literal("sockaddr_in{127.0.0.1,1234,2}".to_string())),
                Box::new(Token::Literal("1".to_string())),
                Box::new(Token::Literal("6".to_string()))
            ])
        )));*/
    }
}
