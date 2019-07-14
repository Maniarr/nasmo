use crate::lexer::token::{Token, Instruction};
use std::ops::Deref;
use core::borrow::{Borrow, BorrowMut};
use std::str::FromStr;
use rand::Rng;

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

fn push_imm64(value: String) -> Vec<Instruction> {
    let mut rng = rand::thread_rng();

    match rng.gen_range(0,2) {
        0 => {
            vec![
                Instruction {
                    mnemonic: "mov".to_string(),
                    operands: vec!["r11".to_string(), format!("0x{}", value)],
                    used_registers: vec![],
                    result_register: "r11".to_string()
                },
                Instruction {
                    mnemonic: "push".to_string(),
                    operands: vec!["r11".to_string()],
                    used_registers: vec!["r11".to_string()],
                    result_register: "rsp".to_string()
                }
            ]
        },
        _ => {
            let (higher, lower) = value.split_at(8);

            let mut instructions = Vec::new();

            if lower == "00000000" {
                match rng.gen_range(0,2) {
                    0 => {
                        instructions.push(
                            Instruction {
                                mnemonic: "xor".to_string(),
                                operands: vec!["r11".to_string(), "r11".to_string()],
                                used_registers: vec![],
                                result_register: "r11".to_string()
                            }
                        );
                        instructions.push(
                            Instruction {
                                mnemonic: "push".to_string(),
                                operands: vec!["r11".to_string()],
                                used_registers: vec!["r11".to_string()],
                                result_register: "rsp".to_string()
                            }
                        )
                    },
                    _ => {
                        instructions.push(
                            Instruction {
                                mnemonic: "push".to_string(),
                                operands: vec!["0".to_string()],
                                used_registers: vec![],
                                result_register: "rsp".to_string()
                            }
                        )
                    }
                }
            } else {
                instructions.push(
                    Instruction {
                        mnemonic: "mov".to_string(),
                        operands: vec!["r11".to_string(), format!("0x{}", lower)],
                        used_registers: vec![],
                        result_register: "r11".to_string()
                    }
                );
                instructions.push(
                    Instruction {
                        mnemonic: "push".to_string(),
                        operands: vec!["r11".to_string()],
                        used_registers: vec!["r11".to_string()],
                        result_register: "rsp".to_string()
                    }
                )
            }

            if higher != "00000000" {
                instructions.push(
                    Instruction {
                        mnemonic: "mov dword".to_string(),
                        operands: vec!["[rsp+4]".to_string(), format!("0x{}", higher)],
                        used_registers: vec!["rsp".to_string()],
                        result_register: "rsp".to_string()
                    }
                );
            }

            instructions
        }
    }
}

pub fn assemble_syscall(token_syscall: Box<Token>) -> Result<Vec<Instruction> , ()> {
    let mut rng = rand::thread_rng();
    let registers = ["rdi", "rsi", "rdx", "r10", "r8", "r9"];

    if let Token::Syscall(syscall_name, parameters) = Box::leak(token_syscall) {
        let (syscall_number, syscall_nb_params) = get_syscall_info(&syscall_name)?;

        let mut tokens = vec![
            Instruction {
                mnemonic: "mov".to_string(),
                operands: vec!["rax".to_string(), syscall_number],
                used_registers: vec![],
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
                                                        let addr_struct = format!("{}{}{:04x}", reverse_hex(format!("{:08x}", ip)), reverse_hex(format!("{:04x}", port)), family);

                                                        tokens.push(
                                                            Instruction {
                                                                mnemonic: "push".to_string(),
                                                                operands: vec!["0".to_string()],
                                                                used_registers: vec![],
                                                                result_register: "rsp".to_string()
                                                            }
                                                        );

                                                        tokens.extend_from_slice(push_imm64(addr_struct).as_slice());

                                                        tokens.push(
                                                            Instruction {
                                                                mnemonic: "mov".to_string(),
                                                                operands: vec![used_register.to_string(), "rsp".to_string()],
                                                                used_registers: vec!["rsp".to_string()],
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
                                    tokens.extend_from_slice(push_imm64(hex_string.clone()).as_slice());

                                    hex_string.clear();
                                }
                            }

                            if hex_string.len() > 0 {
                                tokens.extend_from_slice(push_imm64(hex_string.clone()).as_slice());
                            }

                            tokens.push(
                                Instruction {
                                    mnemonic: "mov".to_string(),
                                    operands: vec![used_register.to_string(), "rsp".to_string()],
                                    used_registers: vec!["rsp".to_string()],
                                    result_register: used_register.to_string()
                                }
                            );
                        } else {
                            if &param == "0" {
                                match rng.gen_range(0, 2) {
                                    0 => {
                                        tokens.push(
                                            Instruction {
                                                mnemonic: "mov".to_string(),
                                                operands: vec![used_register.to_string(), param.to_lowercase().to_string()],
                                                used_registers: vec![],
                                                result_register: used_register.to_string()
                                            }
                                        );
                                    },
                                    1 => {
                                        tokens.push(
                                            Instruction {
                                                mnemonic: "xor".to_string(),
                                                operands: vec![used_register.to_string(), used_register.to_string()],
                                                used_registers: vec![],
                                                result_register: used_register.to_string()
                                            }
                                        );
                                    },
                                    _ => {}
                                }
                            } else {
                                tokens.push(
                                    Instruction {
                                        mnemonic: "mov".to_string(),
                                        operands: vec![used_register.to_string(), param.to_lowercase().to_string()],
                                        used_registers: vec![],
                                        result_register: used_register.to_string()
                                    }
                                );
                            }
                        }
                    },
                    Token::Register(register) => {
                        tokens.push(
                            Instruction {
                                mnemonic: "mov".to_string(),
                                operands: vec![used_register.to_string(), register.to_lowercase().to_string()],
                                used_registers: vec![register.to_lowercase().to_string()],
                                result_register: used_register.to_string()
                            }
                        );
                    },
                    _ => return Err(())
                };
            }

            let mut syscall_registers_used: Vec<String> = registers[..syscall_nb_params].iter().map(|item| item.to_string()).collect();

            syscall_registers_used.push("rax".to_string());

            tokens.push(Instruction {
                mnemonic: "syscall".to_string(),
                operands: vec![],
                used_registers: syscall_registers_used,
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
                    used_registers: vec![result_register],
                    result_register: register_name.to_lowercase()
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
