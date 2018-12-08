extern crate clap;
extern crate elf;
extern crate shellcode;

use clap::{Arg, App, SubCommand, ArgMatches};

use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::path::PathBuf;

fn read_file(path: &PathBuf) -> Result<Vec<u8>, io::Error> {
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();

    f.read_to_end(&mut buffer)?;

    Ok(buffer)
}

fn command_run(command: &ArgMatches) {
    if let Some(args) = command.values_of("file") {
        let mut path = PathBuf::from(args.collect::<String>());

        if command.is_present("object") {
            match read_file(&path) {
                Ok(shellcode) => shellcode::execute_shellcode(&shellcode),
                Err(e) => println!("{}", e)
            }
        } else {
            match shellcode::build_assembly(&path) {
                Ok(path) => {
                    match read_file(&path) {
                        Ok(shellcode) => shellcode::execute_shellcode(&shellcode),
                        Err(e) => println!("{}", e)
                    }
                },
                Err(e) => eprintln!("{}", e)
            }
        }

        return;
    }

    println!("{}", command.usage.clone().unwrap());
}

fn command_export(command: &ArgMatches) {
    if let Some(args) = command.values_of("file") {
        let file_name = args.collect::<String>();

        match read_file(&PathBuf::from(file_name)) {
            Ok(shellcode) => println!("{}", shellcode::Shellcode(shellcode)),
            Err(e) => eprintln!("{}", e)
        }

        return;
    }

    println!("{}", command.usage.clone().unwrap());
}

fn command_extract(command: &ArgMatches) {
    if let Some(args) = command.values_of("file") {
        let file_name = args.collect::<String>();

        match shellcode::extract_shellcode(&PathBuf::from(file_name)) {
            Ok(shellcode) => println!("{}", shellcode::Shellcode(shellcode)),
            Err(e) => eprintln!("{}", e)
        };

        return;
    }

    println!("{}", command.usage.clone().unwrap());
}

fn command_build(command: &ArgMatches) {
    if let Some(args) = command.values_of("file") {
        let file_name = args.collect::<String>();

        if let Err(e) = shellcode::build_assembly(&PathBuf::from(file_name)) {
            eprintln!("{}", e);
        }

        return;
    }

    println!("{}", command.usage.clone().unwrap());
}

fn main() {
    let matches = App::new("nasmo")
        .version("1.0")
        .subcommand(SubCommand::with_name("run")
            .arg(Arg::with_name("file"))
            .arg(Arg::with_name("object")
                .short("o") ))
        .subcommand(SubCommand::with_name("export")
            .arg(Arg::with_name("file")))
        .subcommand(SubCommand::with_name("extract")
            .arg(Arg::with_name("file")))
        .subcommand(SubCommand::with_name("build")
            .arg(Arg::with_name("file")))
    .get_matches();

    if let Some(command) = matches.subcommand_matches("run") {
        command_run(command);

        return;
    }

    if let Some(command) = matches.subcommand_matches("export") {
        command_export(command);

        return;
    } 
    
    if let Some(command) = matches.subcommand_matches("extract") {
        command_extract(command);

        return;
    }

    if let Some(command) = matches.subcommand_matches("build") {
        command_build(command);

        return;
    }

    println!("{}", matches.usage.unwrap());
}    
