// #[panic_handler] — mandatory in no_std binaries.
//
// Any Rust panic in the loader is terminal; abort the whole process with a
// distinctive exit code so operator-side logs can tell a panic apart from a
// clean failure. Must NOT allocate, loop forever, or touch any state.

use core::panic::PanicInfo;

use crate::native::ExitProcess;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { ExitProcess(0xDEAD_BEEF) }
}
