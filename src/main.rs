use anyhow::{Context, Result};
use goblin::pe::PE;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;

const BITNESS: u32 = 64; // 64-bit

fn main() -> Result<()> {
    let src_path = "shellcode0/target/release/shellcode0.exe";
    let mut buffer = get_binary_from_file(src_path)?;

    let pe = PE::parse(&buffer)
        .with_context(|| format!("could not parse the PE file: {}", src_path))?;

    let standard_fileds = pe.header.optional_header.unwrap().standard_fields;

    let entry_offset = standard_fileds.address_of_entry_point - standard_fileds.base_of_code as u32;

    for section in pe.sections {
        let name = String::from_utf8(section.name.to_vec())
            .unwrap_or_else(|_| String::from("Unknown Section"));

        if !name.starts_with(".text") {
            continue;
        }

        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let dst_path = ".\\shellcoed0.bin";
        let shellcode = File::create(dst_path)
            .with_context(|| format!("could not create the file: {}", dst_path))?;
        let mut bootstrap: Vec<u8> = Vec::new();

        /*
         *     ;bootstrap shellcode
         *     call    0x5
         *     pop     rcx
         *     push    rsi
         *     mov     rsi,rsp
         *     and     rsp,0xfffffffffffffff0
         *     sub     rsp,0x20
         *     call    0x5
         *     mov     rsp,rsi
         *     pop     rsi
         *     ret
         */

        bootstrap.extend_from_slice(b"\xE8\x00\x00\x00\x00"); // call 0x5
        bootstrap.extend_from_slice(b"\x59"); // pop rcx
        bootstrap.extend_from_slice(b"\x56"); // push rsi
        bootstrap.extend_from_slice(b"\x48\x89\xE6"); // mov rsi,rsp
        bootstrap.extend_from_slice(b"\x48\x83\xE4\xF0"); // and rsp,0xfffffffffffffff0
        bootstrap.extend_from_slice(b"\x48\x83\xEC\x20"); // sub rsp,0x20
        bootstrap.extend_from_slice(b"\xE8\x00\x00\x00\x00"); // call 0x5
        bootstrap.extend_from_slice(b"\x48\x89\xE4"); // mov rsp,rsi
        bootstrap.extend_from_slice(b"\x5E"); // pop rsi
        bootstrap.extend_from_slice(b"\xC3"); // ret

        let mut buf_writer = BufWriter::new(shellcode);

        // Write the bootstrap shellcode
        buf_writer
            .write_all(&bootstrap)
            .with_context(|| format!("could not write to the file: {}", dst_path))?;

        // Write jump instruction to the entry point
        buf_writer.write(&[0xE9])?; 
        
        for byte in &(entry_offset as u32).to_le_bytes() {
            buf_writer.write(&[*byte])?;
        }

        //main code
        for i in start..(start + size) {
            buf_writer.write(&[buffer[i]])?;
        }
        
        buf_writer.flush()
            .with_context(|| format!("could not flush the file: {}", dst_path))?;

        println!("--------- .text section ---------");
        let binary = &buffer[start..(start + size)];
        maidism::disassemble(binary, 0x0, 0x0, 6, BITNESS, true)?;

        println!("--------- main entry code ---------");
        let binary = &buffer[entry_offset as usize..(entry_offset as usize + size)];
        maidism::disassemble(binary, 0x0, 0x0, 6, BITNESS, true)?;

        println!("--------- shellcode ---------");
        let shellcode = get_binary_from_file(dst_path)?;
        maidism::disassemble(&shellcode, 0x0, 0x0, 16, BITNESS, true)?;

        println!("Shellcode written to: {}", dst_path);

    }
    Ok(())
}


fn get_binary_from_file(file_name: impl Into<String>) -> Result<Vec<u8>> {
    let file_name = file_name.into();
    let mut f = File::open(&file_name)
        .with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)
        .with_context(|| format!("could not reading from the file: {}", &file_name))?;
    Ok(buffer)
}