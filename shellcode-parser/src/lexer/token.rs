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
    mnemonic: String,
    operands: Vec<String>,
    registers: Vec<String>
}
