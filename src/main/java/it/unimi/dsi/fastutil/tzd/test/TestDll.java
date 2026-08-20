package it.unimi.dsi.fastutil.tzd.test;

// Test: load seckill_native.dll and call its JNI functions
import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;

public class TestDll {
    public static void main(String[] args) throws Exception {
        System.err.println("=== TZD DLL Test ===");

        // Phase 1: Unsafe defense (no DLL needed)
        UnsafeGateway.bootstrap();
        System.err.println("Unsafe: " + UnsafeGateway.isAvailable());
        UnsafeGateway.verifyLoadChain();

        // Load the DLL
        String dllPath = args.length > 0 ? args[0] : null;
        if (dllPath == null) {
            // Try to find it in the build output
            dllPath = "F:/秒杀/aitest/seckill_mod/native/seckill_native.dll";
        }
        System.err.println("Loading DLL: " + dllPath);
        System.load(dllPath);
        System.err.println("DLL loaded OK");

        // Test getJvmtiVersion0 — should return JVMTI version if JNI_OnLoad succeeded
        try {
            int ver = NativeBridge.getJvmtiVersion0();
            System.err.println("JVMTI version: 0x" + Integer.toHexString(ver)
                    + (ver != 0 ? " (READY)" : " (NOT READY)"));
        } catch (UnsatisfiedLinkError e) {
            System.err.println("getJvmtiVersion0 failed: " + e.getMessage());
        }

        // Test getJvmBaseAddress0 — should return jvm.dll base address
        try {
            long base = NativeBridge.getJvmBaseAddress0();
            System.err.println("jvm.dll base: 0x" + Long.toHexString(base));
        } catch (UnsatisfiedLinkError e) {
            System.err.println("getJvmBaseAddress0 failed: " + e.getMessage());
        }

        // Test installMemoryGuard0 — installs inline hooks on VirtualProtect etc.
        try {
            NativeBridge.installMemoryGuard0();
            System.err.println("memory guard installed OK");
            // Check block count
            long blocks = NativeBridge.getMemoryGuardBlockCount0();
            System.err.println("block count: " + blocks);
        } catch (UnsatisfiedLinkError e) {
            System.err.println("installMemoryGuard0 failed: " + e.getMessage());
        } catch (Throwable t) {
            System.err.println("installMemoryGuard0 error: " + t);
        }

        // Test startHookScanner0 — starts background scanner thread
        try {
            NativeBridge.startHookScanner0();
            System.err.println("hook scanner started OK");
            // Let it run for 3 seconds
            Thread.sleep(3000);
            long repairs = NativeBridge.getHookScannerRepairCount0();
            System.err.println("repair count after 3s: " + repairs);
            // Stop scanner
            NativeBridge.stopHookScanner0();
            System.err.println("hook scanner stopped OK");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("scanner failed: " + e.getMessage());
        } catch (Throwable t) {
            System.err.println("scanner error: " + t);
        }

        // Test methodDetectOffsets0 — detects Method* field offsets
        try {
            NativeBridge.methodDetectOffsets0();
            System.err.println("method offsets detected OK");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("methodDetectOffsets0 failed: " + e.getMessage());
        } catch (Throwable t) {
            System.err.println("methodDetectOffsets0 error: " + t);
        }

        System.err.println("=== DLL Test complete — no crash ===");
    }
}
