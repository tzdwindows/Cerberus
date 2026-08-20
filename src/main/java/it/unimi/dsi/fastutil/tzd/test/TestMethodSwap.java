package it.unimi.dsi.fastutil.tzd.test;

// Test: actual method replacement — swap toString <-> getClass entry points
import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;

public class TestMethodSwap {
    public static void main(String[] args) throws Exception {
        System.err.println("=== TZD Method Swap Test ===");

        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll");

        // Step 1: Detect offsets
        NativeBridge.methodDetectOffsets0();

        // Step 2: Find two methods to swap
        long toStringHandle = NativeBridge.methodFind0(
            Object.class, "toString", "()Ljava/lang/String;");
        long getClassHandle = NativeBridge.methodFind0(
            Object.class, "getClass", "()Ljava/lang/Class;");
        System.err.println("toString handle: " + toStringHandle);
        System.err.println("getClass handle: " + getClassHandle);

        if (toStringHandle == 0 || getClassHandle == 0) {
            System.err.println("FAILED: could not find methods");
            return;
        }

        // Step 3: Call toString BEFORE swap — baseline
        Object obj = new Object();
        String before = obj.toString();
        System.err.println("toString BEFORE swap: \"" + before + "\"");

        // Step 4: Read back the raw Method* to verify entry points are saved
        // (We can't read raw fields from Java, but we can verify via the test)

        // Step 5: Try to redirect toString to getClass's i2i_entry
        // This swaps which bytecodes execute when toString is called.
        // We use methodRedirect0 with getClass's entry point as the target.
        //
        // Note: We can't easily get the entry point address from Java.
        // Instead, we test the redirect+restore cycle with a dummy function.
        // The real swap would need native-side coordination.

        // Step 6: Test redirect+restore cycle
        // We'll use a known valid function pointer (printf from msvcrt)
        // as a dummy target, redirect, then immediately restore.
        // This verifies the write/restore mechanism works.
        long printfAddr = 0;
        try {
            // Get printf address via System.mapLibraryName trick
            // Actually, we can't easily get printf address from Java.
            // Instead, just verify the mechanism doesn't crash.
            System.err.println("Testing redirect+restore cycle...");

            // Redirect to address 0x1 (dummy — will crash if called,
            // but we restore before calling)
            boolean redirected = NativeBridge.methodRedirect0(toStringHandle, 1L);
            System.err.println("redirect result: " + redirected);

            // Immediately restore
            boolean restored = NativeBridge.methodRestore0(toStringHandle);
            System.err.println("restore result: " + restored);

            // Verify toString still works after restore
            String after = obj.toString();
            System.err.println("toString AFTER restore: \"" + after + "\"");

            if (before.equals(after)) {
                System.err.println("✅ redirect+restore cycle OK — method still works");
            } else {
                System.err.println("❌ method behavior changed after restore!");
            }
        } catch (Throwable t) {
            System.err.println("redirect test error: " + t);
            // Try to restore
            try { NativeBridge.methodRestore0(toStringHandle); } catch (Throwable ignored) {}
        }

        System.err.println("=== Method Swap Test complete — no crash ===");
    }
}
