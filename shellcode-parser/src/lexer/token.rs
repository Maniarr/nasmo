use std::cmp;

#[derive(Debug)]
pub enum Register<'a> {
    Register8(&'a str),
    Register16(&'a str),
    Register32(&'a str),
    Register64(&'a str),

    SegmentRegister(&'a str),

    ControlRegister(u8),

    RFlagsRegister,
}

#[derive(Debug, PartialEq)]
pub enum Instruction {
    Mov,
}
