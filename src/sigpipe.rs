/// Restore default SIGPIPE handling so piped output (`fort list | head`)
/// terminates quietly instead of panicking on EPIPE.
#[cfg(unix)]
pub fn restore_default() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
pub fn restore_default() {}
