fn main() {
    if let Err(error) = fort::cli::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
