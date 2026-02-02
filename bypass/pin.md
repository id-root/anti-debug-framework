# Bypassing Anti-Debug with Intel Pin

## Threat Model
Intel Pin is a Dynamic Binary Instrumentation (DBI) framework. It JIT-compiles the application code, inserting instrumentation.
- **Overhead**: Massive timing overhead (10x-100x).
- **Code Cache**: Code is executed from a cache, not original memory. (RIP relative addressing issues are handled by Pin, but introspection might see the original or the cache depending on how it's done).

## Detection Logic
- **Timing**: `check_rdtsc_timing` will trigger heavily due to JIT overhead.
- **Int3**: Pin doesn't necessarily insert Int3s, but it might modify code layout.
- **RIP**: If we read `RIP`, we might see the code cache address (though Pin tries to hide this).

## Bypass Techniques

### 1. Instruction Hooking
Write a Pin Tool to hook `rdtsc`.
```cpp
VOID FakeRDTSC(CONTEXT *ctxt) {
    // Set RAX/RDX to simulated time
    PIN_SetContextReg(ctxt, REG_RAX, low_part);
    PIN_SetContextReg(ctxt, REG_RDX, high_part);
    PIN_ExecuteAt(ctxt); // Skip original RDTSC
}
```
This allows complete control over the time perception of the malware.

### 2. Scanners
If the malware scans memory (`scan_for_int3`), Pin provides APIs to let the tool read the *original* image vs the *instrumented* image. Pin generally hides its artifacts from the application's read operations (transparency), so `scan_for_int3` might actually *fail* to find Pin artifacts unless Pin is configured poorly.

### 3. General Evasion
The sheer slowness of Pin is its biggest tell. Bypassing timing checks usually requires:
- Skipping the check (NOPing via Pin).
- Speeding up the emulation (impossible).
- Hooking the timing source (RDTSC) to return "fast" values.
