#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

mod binds;
mod utils;
use binds::*;
use core::arch::asm;
use core::mem::transmute;
use core::panic::PanicInfo;
use utf16_literal::utf16;
use utils::*;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // 在这里可以添加自定义的 panic 处理逻辑
    loop {}
}

const USER32_DLL: &[u8] = b"user32.dll\0";
const OutputDebugStringA_: &[u8] = b"OutputDebugStringA\0";
const LoadLibraryA_: &[u8] = b"LoadLibraryA\0";
const GetProcAddress_: &[u8] = b"GetProcAddress\0";
const MessageBoxW_: &[u8] = b"MessageBoxW\0";

pub type PLoadLibraryA = unsafe extern "system" fn(LPCSTR) -> HMODULE;

pub type PGetProcAddress = unsafe extern "system" fn(HMODULE, LPCSTR) -> LPVOID;

pub type MessageBoxW =
    unsafe extern "system" fn(hWnd: PVOID, lpText: LPCSTR, lpCaption: LPCSTR, uType: u32) -> u32;

//pub type OutputDebugStringAFn = unsafe extern "C" fn(*const i8);

//pub type DbgPrintFn = unsafe extern "C" fn(Format: *const i8, ...) -> NTSTATUS;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn main() {
    unsafe {
        let kernel32 = get_module_by_name(utf16!("KERNEL32.DLL\0").as_ptr());

        let LoadLibraryA: PLoadLibraryA =
            transmute(get_func_by_name(kernel32, LoadLibraryA_.as_ptr() as _));

        let GetProcAddress: PGetProcAddress =
            transmute(get_func_by_name(kernel32, GetProcAddress_.as_ptr() as _));

        let user32 = LoadLibraryA(USER32_DLL.as_ptr() as _);

        let MessageBoxW: MessageBoxW =
            transmute(GetProcAddress(user32, MessageBoxW_.as_ptr() as _));

        MessageBoxW(
            NULL,
            utf16!("Hello, World!\0").as_ptr() as _,
            utf16!("MessageBoxW from shellcode Example\0").as_ptr() as _,
            0,
        );
    }
}

unsafe fn get_module_by_name(module_name: *const u16) -> PVOID {
    unsafe {
        // 获取当前进程的 PEB（Process Environment Block）指针
        let mut ppeb: *mut PEB = core::ptr::null_mut();

        // 使用 inline assembly 获取 PEB 指针
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) ppeb,
        );

        // 获取 PEB 中的 LDR（Loader）数据结构指针
        let p_peb_ldr_data = (*ppeb).Ldr;

        // 获取 LDR 中的 InLoadOrderModuleList 链表头
        let mut module_list =
            (*p_peb_ldr_data).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

        // 遍历链表，查找匹配的模块名
        while (*module_list).DllBase != NULL {
            let dll_name = (*module_list).BaseDllName.Buffer;

            if compare_raw_str(module_name, dll_name) {
                return (*module_list).DllBase;
            }

            module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
        }
    }

    NULL
}

unsafe fn get_func_by_name(module: PVOID, func_name: *const u8) -> PVOID {
    unsafe {
        // 获取模块的 NT 头部
        let nt_header = (module as u64 + (*(module as *mut IMAGE_DOS_HEADER)).e_lfanew as u64)
            as *mut IMAGE_NT_HEADERS64;

        // 导出目录的 RVA（Relative Virtual Address）通常在 OptionalHeader.DataDirectory[0] 中
        let export_dir_rva = (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress as u64;

        // 检查导出目录的 RVA 是否为 0
        if export_dir_rva == 0x0 {
            return NULL;
        };

        // 获取导出目录的指针
        let export_dir = (module as u64 + export_dir_rva) as *mut IMAGE_EXPORT_DIRECTORY;

        let number_of_names = (*export_dir).NumberOfNames;
        let addr_of_funcs = (*export_dir).AddressOfFunctions;
        let addr_of_names = (*export_dir).AddressOfNames;
        let addr_of_ords = (*export_dir).AddressOfNameOrdinals;

        for i in 0..number_of_names {
            let name_rva_p: *const DWORD =
                (module as *const u8).offset((addr_of_names + i * 4) as isize) as *const _;
            let name_index_p: *const WORD =
                (module as *const u8).offset((addr_of_ords + i * 2) as isize) as *const _;
            let name_index = name_index_p.as_ref().unwrap();
            let mut off: u32 = (4 * name_index) as u32;
            off = off + addr_of_funcs;
            let func_rva: *const DWORD = (module as *const u8).offset(off as _) as *const _;

            let name_rva = name_rva_p.as_ref().unwrap();
            let curr_name = (module as *const u8).offset(*name_rva as isize);

            if *curr_name == 0 {
                continue;
            }

            // 使用 compare_raw_str 函数比较函数名
            if compare_raw_str(func_name, curr_name) {
                let res = (module as *const u8).offset(*func_rva as isize);
                return res as _;
            }
        }
    }

    return NULL;
}


unsafe fn find_func<T>(module_name: &str, func_name: &str) -> T {
    let module = get_module_by_name(to_utf16z(module_name).as_ptr());
    if module.is_null() {
        panic!("Module not found: {}", module_name);
    }

    let addr = get_func_by_name(module, to_ascii_z(func_name).as_ptr());
    if addr.is_null() {
        panic!("Function not found: {}", func_name);
    }

    transmute(addr)
}

