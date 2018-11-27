extern crate elf;
extern crate mmap;

use std::{fmt, fs, mem, ptr};
use std::fs::File;
use std::path::PathBuf;
use mmap::*;
use std::process::Command;
use std::io::Write;

pub struct Shellcode(pub Vec<u8>);

impl fmt::Display for Shellcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[] Size: {} bytes:\n", self.0.len());
        self.0.iter().map(|byte| write!(f, "\\x{}", format!("{:02X}", byte))).collect::<fmt::Result>()
    }
}

impl fmt::Debug for Shellcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

pub fn execute_shellcode(shellcode: &[u8]) {
    let mapping = MemoryMap::new(shellcode.len(), &[
        MapOption::MapReadable,
        MapOption::MapWritable,
        MapOption::MapExecutable
    ]).unwrap();

    println!("[ ] Size: {} bytes\n[+] Running ...", shellcode.len());

    unsafe {
        ptr::copy(shellcode.as_ptr(), mapping.data(), shellcode.len());
        mem::transmute::<_, fn()>(mapping.data())();
    }
}

pub fn extract_shellcode(path: &PathBuf) -> Result<Shellcode, String> {
    match elf::File::open_path(path) {
        Ok(file)    => {
            match file.get_section(".text") {
                Some(section)   => Ok(Shellcode(section.data.clone())),
                None            => Err("Failed to look up .text section".to_string())
            }
        },
        Err(e)      => Err(format!("Error: {:?}", e))
    }
}

pub fn build_assembly(path: &PathBuf) -> Result<PathBuf, String> {
    let mut path_object = path.clone();
    let mut path_bin = path.clone();

    path_object.set_extension("o");
    path_bin.set_extension("bin");

    println!("[ ] Building ...");

    let result_output = Command::new("nasm")
        .arg("-f elf64")
        .arg(format!("-o {}", &path_object.to_str().unwrap()))
        .arg(&path)
        .output();

    match result_output {
        Ok(_) => {
             match extract_shellcode(&path_object) {
                Ok(shellcode) => {
                    let _ = fs::remove_file(&path_object);

                    match File::create(&path_bin) {
                        Ok(mut file) => {
                            if let Err(_) = file.write_all(&shellcode.0) {
                                return Err("Write error".to_string());
                            }

                            Ok(PathBuf::from(&path_bin))
                        },
                        Err(e) => {
                            Err(format!("{}", e))
                        }
                    }
                },
                Err(e) => Err(format!("{}", e))
            }
        },
        Err(e) => {
            Err(format!("{}", e))
        }
    }   
}
