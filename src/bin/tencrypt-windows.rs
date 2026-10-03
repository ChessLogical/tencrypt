#[cfg(not(target_os = "windows"))]
compile_error!("tencrypt-windows must be built for a Windows target");

fn main() -> std::process::ExitCode {
    tencrypt::entry()
}
