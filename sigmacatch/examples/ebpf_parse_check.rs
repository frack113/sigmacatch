// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Parse-check for the embedded probe object (no privileges needed until
//! map creation; run with the ebpf feature).

use aya::Ebpf;

fn main() {
    let object = include_bytes!(concat!(env!("OUT_DIR"), "/sigmacatch_ebpf.o"));
    println!("object size: {} bytes", object.len());
    match EbpfLoader_ext::load(object) {
        Ok(ebpf) => {
            println!("parse OK");
            println!("EVENTS map present: {}", ebpf.map("EVENTS").is_some());
            for name in ["EXEC_ARGS", "STAGE_SCRATCH"] {
                println!("{name} map present: {}", ebpf.map(name).is_some());
            }
            for name in [
                "sys_enter_execve",
                "sched_process_exec",
                "sched_process_exit",
            ] {
                println!("program {name} present: {}", ebpf.program(name).is_some());
            }
        }
        Err(e) => {
            eprintln!("PARSE FAILED: {e:#}");
            std::process::exit(1);
        }
    }
}

#[allow(non_camel_case_types)]
struct EbpfLoader_ext;

impl EbpfLoader_ext {
    fn load(object: &'static [u8]) -> Result<Ebpf, aya::EbpfError> {
        aya::EbpfLoader::new().load(object)
    }
}
