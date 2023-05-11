use wasmtime::*;
use wasmtime_wasi::WasiCtx;
use wasmtime_wasi::sync::WasiCtxBuilder;
use std::marker;

pub struct WasmInstance<T>{
    pub store: Store<WasiCtx>,
    memory: Memory,
    init_write: TypedFunc<i32,i32>,
    get_string: TypedFunc<(),i32>,
    get_string_len: TypedFunc<(),i32>,
    run_handler: TypedFunc<i32,()>,
    _marker: marker::PhantomData<fn() -> T>,
}


impl<T> WasmInstance<T> {
    pub fn new() -> WasmInstance<T>{
        let engine = Engine::default();
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s).unwrap();

        let wasi = WasiCtxBuilder::new()
        .inherit_stdio()
        .inherit_args().unwrap()
        .build();
        let mut store = Store::new(&engine, wasi);
        let module = Module::from_file(&engine, "target/wasm32-wasi/debug/capable_wasm.wasm").unwrap();
        let instance = linker.instantiate(&mut store, &module).unwrap();
        linker.instance(&mut store, "", instance).unwrap();

        let memory = instance.get_memory(&mut store,"memory")
        .ok_or(anyhow::format_err!("failed to find `memory` export")).unwrap();
        let init_write = instance.get_typed_func::<i32, i32>(&mut store, "init_write").unwrap();
        let get_string = instance.get_typed_func::<(), i32>(&mut store, "get_string").unwrap();
        let get_string_len = instance.get_typed_func::<(), i32>(&mut store, "get_string_len").unwrap();
        let run_handler = instance.get_typed_func::<i32, ()>(&mut store, "run_handler").unwrap();
        WasmInstance {
            store,
            memory,
            init_write,
            get_string,
            get_string_len,
            run_handler,
            _marker: marker::PhantomData,
        }
    }
    
    pub fn write_data_to_wasm(&mut self,write_buffer : &[u8]){
        let write_addr = self.init_write.call(&mut self.store,write_buffer.len().try_into().unwrap()).unwrap();
        self.memory.write(&mut self.store,write_addr.try_into().unwrap(),write_buffer).unwrap();
    }

    pub fn read_from_wasm(&mut self)->String{
        let read_addr= self.get_string.call(&mut self.store,()).unwrap();
        let len= self.get_string_len.call(&mut self.store,()).unwrap();
        let mut read_buffer = vec![0u8; len.try_into().unwrap()];
        self.memory.read(&self.store, read_addr.try_into().unwrap(), &mut read_buffer).unwrap();
        format!("{}",std::str::from_utf8(&read_buffer[..]).unwrap())
    }

    pub fn run(&mut self,extra_fields: i32) {
        self.run_handler.call(&mut self.store, extra_fields).unwrap();
    }
}