fn main() {
    if !cfg!(target_os = "linux") {
        panic!("This crate only supports Linux");
    }
}
