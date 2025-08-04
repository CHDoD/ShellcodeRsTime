#![allow(dead_code)]

///
/// 获取宽字符指针（Windows 内核常用宽字符表示路径 / 模块名）的长度。
///
///
unsafe fn u16_ptr_len(ptr: *const u16) -> usize {
    let len = (0..).take_while(|&i| !(*ptr.offset(i)).is_null()).count();
    len
}

///
/// 比较 Rust 字符串和宽字符指针（Windows 内核常用宽字符表示路径 / 模块名）。
///

fn compare_str_u16(s: &str, u: *const u16) -> bool {
    unsafe {
        if u.is_null() {
            return false;
        }

        let u_len = u16_ptr_len(u);
        if u_len != s.len() {
            return false;
        }

        for i in 0..u_len {
            if *u.offset(i as isize) != s.as_bytes()[i] as u16 {
                return false;
            }
        }
    }
    true
}

///
/// 将 Rust 字符串转换为宽字符指针（Windows 内核常用宽字符表示路径 / 模块名）。
/// 如果允许使用 alloc（堆分配）：
///
/*
pub fn str_to_utf16_null_terminated(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}
*/
///
/// aruments:
/// - `s`: Rust 字符串。
/// - `buf`: 目标缓冲区，必须足够大以容纳转换后的宽字符和结尾的空字符。
///

pub fn str_to_u16_ptr(s: &str, buf: &mut [u16]) {
    let len = s.encode_utf16().count();
    assert!(buf.len() >= len + 1); // 要求目标 buf 足够大
    for (i, c) in s.encode_utf16().enumerate() {
        buf[i] = c;
    }
    buf[len] = 0;
}

///
/// 比较两个原始字符串（支持字节或宽字节），用于匹配模块名（宽字符）和函数名（字节）。
///
/// arguments:
/// - `s`: 指向第一个字符串的指针。
/// - `u`: 指向第二个字符串的指针。
///
use num_traits::Num;

pub fn compare_raw_str<T>(s: *const T, u: *const T) -> bool
where
    T: Num,
{
    unsafe {
        if s.is_null() || u.is_null() {
            return false;
        }

        let u_len = (0..).take_while(|&i| !(*u.offset(i)).is_zero).count();
        let u_slice = core::slice::from_raw_parts(u, u_len);
        let s_len = (0..).take_while(|&i| !(*s.offset(i)).is_zero).count();
        let s_slice = core::slice::from_raw_parts(s, s_len);
        if u_len != s_len {
            return false;
        }

        for i in 0..s_len {
            if s_slice[i] != u_slice[i] {
                return false;
            }
        }
    }
    true
}

pub fn to_ascii_z(s: &str) -> &[u8] {
    // 返回 null 结尾的 ASCII 字符串
    use core::slice;

    let len = s.len();
    let ptr = s.as_ptr();

    unsafe {
        // 静态分配一块内存空间（简化实现，你也可以用栈或全局内存）
        // 实际项目里建议用更安全的做法，比如栈上写个临时 buf
        let mut buf = [0u8; 256];
        core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), len);
        buf[len] = 0;
        &buf[..=len] // 包含末尾 \0
    }
}
