extern crate shellcode;
extern crate rand;

use shellcode::Shellcode;
use rand::{thread_rng, seq};
use std::fs::File;
use std::io::Write;

trait Polymorphe {
    fn encode(&self) -> Vec<u8>;
    fn get_decoder(&self) -> Result<Vec<u8>, String>;
    fn modify(&self) -> Result<Vec<u8>, String>;
}

struct AddPolymorphe {
    number: u8,
    shellcode: Vec<u8>
}

impl AddPolymorphe {
    fn new(shellcode: Vec<u8>) -> AddPolymorphe {
        let mut rng = thread_rng();
        let number = seq::sample_iter(&mut rng, AddPolymorphe::get_add_value(&shellcode), 1).unwrap()[0];

        AddPolymorphe {
            number: number,
            shellcode: shellcode.clone()
        }
    }

    fn get_used_bytes(shellcode: &Vec<u8>) -> Vec<u8> {
        let mut bytes = shellcode.clone();
        
        bytes.sort();
        bytes.dedup();

        bytes
    }

    fn get_add_value(shellcode: &Vec<u8>) -> Vec<u8> {
        let impossible_bytes: Vec<u8> = AddPolymorphe::get_used_bytes(shellcode).into_iter().map(|b| 0u8.wrapping_sub(b)).collect();

        let mut possibilities = (u8::min_value()..=u8::max_value()).collect::<Vec<u8>>();

        possibilities.retain(|x| !impossible_bytes.contains(&x));

        possibilities
    }

}

impl Polymorphe for AddPolymorphe {
    fn get_decoder(&self) -> Result<Vec<u8>, String> {
        let asm = format!("jmp init
routine:
    pop rsi
    xor rcx, rcx
    push {}
    pop rcx

decode:
    sub byte [rsi + rcx - 1], {}
    dec rcx
    jnz decode
    jmp main 

init:
    call routine

main:", self.shellcode.len(), self.number);

        shellcode::assembly(asm)
    }

    fn encode(&self) -> Vec<u8> {
        self.shellcode.clone().into_iter().map(|b| b.wrapping_add(self.number)).collect()
    }

    fn modify(&self) -> Result<Vec<u8>, String> {
        match self.get_decoder() {
            Ok(mut decoder) => {
                println!("{:?}", &decoder);
                decoder.extend(self.encode());

                println!("{:?}", &decoder);

                Ok(decoder)
            },
            Err(e) => Err(format!("{}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use shellcode::Shellcode;

    use super::*;

    #[test]
    fn it_works() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("fixtures/hello_world.bin");

        let mut f = File::open(path).unwrap();
        let mut buffer = Vec::new();

        f.read_to_end(&mut buffer).unwrap();

        let mut poly = AddPolymorphe::new(buffer);

        match poly.modify() {
            Ok(shellcode) => {
                match File::create("test.poly.bin") {
                    Ok(mut file) => {
                        file.write_all(&shellcode);
                    },
                    Err(_) => {}
                }
            },
            Err(_) => {}
        };
    }
}
