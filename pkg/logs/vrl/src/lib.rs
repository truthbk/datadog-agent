extern crate alloc;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ffi::CString;
use value::{Secrets, Value};
use vrl::diagnostic::Formatter;
use vrl::Program;
use vrl::TimeZone;
use vrl::{state, Runtime, TargetValueRef};

#[no_mangle]
pub extern "C" fn compile_vrl_c(input: *const libc::c_char) -> *mut Program {
    let program_string = unsafe { CStr::from_ptr(input) }.to_str().unwrap();
    let functions = vrl_stdlib::all();
    match vrl::compile(&program_string, &functions) {
        Ok(res) => {
            return Box::into_raw(Box::new(res.program));
        }
        Err(err) => {
            let f = Formatter::new(&"", err);
            panic!("{:#}", f)
        }
    }
}

#[no_mangle]
pub extern "C" fn run_vrl_c(
    input: *const libc::c_char,
    program: *mut Program,
) -> *const libc::c_char {
    let prog = unsafe { program.as_ref().unwrap() };
    let inpt: &CStr = unsafe { CStr::from_ptr(input) };
    let output = run_vrl(inpt.to_str().unwrap(), prog);
    let c_str = CString::new(output.as_bytes()).expect("CString::new failed");
    return c_str.into_raw();
}

fn run_vrl(s: &str, program: &Program) -> String {
    let mut value: Value = Value::from(s);
    let mut metadata = Value::Object(BTreeMap::new());
    let mut secrets = Secrets::new();
    let mut target = TargetValueRef {
        value: &mut value,
        metadata: &mut metadata,
        secrets: &mut secrets,
    };

    let output =
        Runtime::new(state::Runtime::default()).resolve(&mut target, program, &TimeZone::Local);

    return output.unwrap().to_string();
}
