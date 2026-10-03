#[cfg(not(target_os = "linux"))]
compile_error!("tencrypt-linux must be built for a Linux target");

fn main() -> std::process::ExitCode {
    tencrypt::entry()
}
