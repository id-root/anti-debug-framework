fn main() {
    cc::Build::new()
        .file("asm/rdtsc.s")
        .file("asm/scan_int3.s")
        .file("asm/trap_flag.s")
        .file("asm/regs.s")
        .file("asm/debug_regs.s")
        .file("asm/micro_timing.s")
        .compile("antidebug_asm");
    
    println!("cargo:rerun-if-changed=asm/rdtsc.s");
    println!("cargo:rerun-if-changed=asm/scan_int3.s");
    println!("cargo:rerun-if-changed=asm/trap_flag.s");
    println!("cargo:rerun-if-changed=asm/regs.s");
    println!("cargo:rerun-if-changed=asm/debug_regs.s");
    println!("cargo:rerun-if-changed=asm/micro_timing.s");
}
