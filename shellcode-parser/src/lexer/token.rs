use std::cmp;

#[derive(Debug, PartialEq)]
pub enum Register {
    GeneralRegister(u8),
    GeneralRegister8L(char),
    GeneralRegister8H(char),
    GeneralRegister16(char),
    GeneralRegister32(char),
    GeneralRegister64(char),

    SegmentRegister(char)
}

#[derive(Debug, PartialEq)]
pub enum Instruction {
    Mov,
}
