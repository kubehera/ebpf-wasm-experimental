// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

pub use self::imp::*;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(clippy::transmute_ptr_to_ref)]
#[allow(clippy::upper_case_acronyms)]
mod imp {
    pub mod capable_bss_types {
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct bss {
            pub _event: event,
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct event {
            pub tgid: u32,
            pub pid: i32,
            pub uid: u32,
            pub cap: i32,
            pub audit: i32,
            pub insetid: i32,
            pub comm: [u8; 16],
            pub kernel_stack_id: i32,
            pub user_stack_id: i32,
        }
    }

    pub mod capable_kconfig_types {
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct kconfig {
            pub LINUX_KERNEL_VERSION: i32,
        }
    }
}
