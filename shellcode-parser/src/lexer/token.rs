#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Register(String),
    Assignation(Box<Token>, Box<Token>),
    Group(Vec<Box<Token>>),
    Literal(String),
    Syscall(String, Vec<Box<Token>>)
}

#[derive(Debug)]
pub struct Instruction {
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub used_registers: Vec<String>,
    pub result_register: String
}

/*
    mov rax, 41                         ; R9 = SYSCALL SOCKET 2 1 6
    mov rdi, 2
    mov rsi, 1
    mov rdx, 6
    syscall
*/
