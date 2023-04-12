#![feature(wasm_target_feature)]

use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref READ_BUF: Mutex<String> = Mutex::new(String::from("Hello, world!"));
    static ref WRITE_BUF: Mutex<Vec<u8>> = Mutex::new(vec![0u8;0]);
}

/*#[no_mangle]
pub extern fn get_write_addr() -> *const u8 {
    WRITE_BUF.lock().unwrap().as_ptr()
}
*/

#[no_mangle]
pub unsafe extern fn init_write(len: usize) -> *const u8 {
    let mut write = WRITE_BUF.lock().unwrap();
    *write=Vec::with_capacity(len);
    write.set_len(len);
    write.as_ptr()
}

#[no_mangle]
pub extern fn get_string() -> (usize, *const u8){
    let read = READ_BUF.lock().unwrap();
    let binding = read.to_owned();
    let bytes = binding.as_bytes();
    return (bytes.len(), read.as_ptr())
}

/*
#[no_mangle]
pub extern fn get_string_addr() ->  *mut u8{
    READ_BUF.lock().unwrap().as_mut_ptr()
} */

#[no_mangle]
pub unsafe extern "C" fn greet(){
    let mut read = READ_BUF.lock().unwrap();
    let write = WRITE_BUF.lock().unwrap().to_owned();
    *read = format!("hello name: {}",std::str::from_utf8(&write).unwrap());
}