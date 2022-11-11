package vrl

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <vrl.h>
//#cgo CFLAGS: -I${SRCDIR}/pkg/logs/vrl/target/release/
//#cgo darwin LDFLAGS: -L${SRCDIR}/target/aarch64-apple-darwin/release -Wl,-rpath,${SRCDIR}/target/aarch64-apple-darwin/release -lvrl_bridge
import "C"
import "unsafe"

type VrlProgram struct{ p unsafe.Pointer }

func CompileVrl(str string) VrlProgram {
	cs := C.CString(str)
	program := unsafe.Pointer(C.compile_vrl_c(cs))
	return VrlProgram{p: program}
}

func Run(program VrlProgram, str string) string {
	cs := C.CString(str)
	b := C.run_vrl_c(cs, program.p)
	s := C.GoString(b)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(b))
	return s
}
