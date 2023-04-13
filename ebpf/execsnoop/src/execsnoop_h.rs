#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct event {
    pub comm: [u8; 16],
    pub pid: i32,
    pub retval: i32,
    pub args_count: i32,
    pub args_size: u32,
    //pub args: [u8; 16],
    //pub args: [u8; 7680],
}