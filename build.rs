use cc::Build;

fn main() {
    #[cfg(target_arch = "x86_64")]
    {
        Build::new()
            .file("src/aes_low_level/vaes.c")
            .compile("vaes");
    }
}
