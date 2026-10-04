fn main() {
    println!("cargo:rerun-if-changed=native/wfp_control.c");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    cc::Build::new()
        .file("native/wfp_control.c")
        .define("NEXUS_WFP_LIBRARY", None)
        .warnings(true)
        .compile("nexus_wfp");

    println!("cargo:rustc-link-lib=fwpuclnt");
    println!("cargo:rustc-link-lib=ws2_32");
    println!("cargo:rustc-link-lib=rpcrt4");
    println!("cargo:rustc-link-lib=uuid");
}
