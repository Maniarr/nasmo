use crate::lexer::token::{Token, Instruction};
use std::ops::Deref;
use core::borrow::{Borrow, BorrowMut};

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

fn assemble_syscall(token_syscall: Box<Token>) -> Result<Vec<Instruction> , ()> {
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
                if let Token::Literal(param) = item.deref() {
                    let used_register = registers[i];

                    tokens.push(
                        Instruction {
                            mnemonic: "mov".to_string(),
                            operands: vec![used_register.to_string(), param.to_string()],
                            used_registers: vec![used_register.to_string()],
                            result_register: used_register.to_string()
                        }
                    );
                } else {
                    return Err(());
                }
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

fn assemble_assignation(token_assignation: Box<Token>) -> Result<Vec<Instruction> , ()> {
    let mut tokens = Vec::new();

    if let Token::Assignation(destination_token, source_tokens) = *token_assignation {
        tokens.append(&mut assemble_syscall(source_tokens.clone())?);

        if let Some(instruction) = tokens.last().clone() {
            let result_register = instruction.result_register.to_string();

            if let Token::Register(register_name) = *destination_token.clone() {
                tokens.push(Instruction {
                    mnemonic: "mov".to_string(),
                    operands: vec![register_name.clone(), result_register.clone()],
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
        dbg!(assemble_assignation(Box::new(
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
        )));
    }
}
