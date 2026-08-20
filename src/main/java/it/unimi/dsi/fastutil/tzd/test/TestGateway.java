package it.unimi.dsi.fastutil.tzd.test;

// Test: verify UnsafeGateway runs without crashing on JDK 20
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import sun.misc.Unsafe;

public class TestGateway {
    public static void main(String[] args) {
        System.err.println("=== TZD UnsafeGateway Test ===");

        // Test 1: bootstrap (get Unsafe via reflection — no DLL needed)
        UnsafeGateway.bootstrap();
        System.err.println("Unsafe available: " + UnsafeGateway.isAvailable());

        if (UnsafeGateway.isAvailable()) {
            Unsafe u = UnsafeGateway.getUnsafe();
            System.err.println("Unsafe addressSize: " + u.addressSize());

            // Test 2: jvm.dll base (should be 0 — native code will detect it)
            long base = UnsafeGateway.getJvmBase();
            System.err.println("jvm.dll base: " + base + " (0 = not detected in Java, native code handles it)");

            // Test 3: load chain verification
            // Verifies ClassLoader$NativeLibrary.load is still native
            boolean loadOk = UnsafeGateway.verifyLoadChain();
            System.err.println("Load chain verified: " + loadOk);

            // Test 4: ghost class definition (safe — uses MethodHandles)
            // This would need bytecode to define — skip for now, just verify
            // the method exists and doesn't crash with null input.
            Class<?> ghost = UnsafeGateway.defineGhostClass(
                UnsafeGateway.class, null);
            System.err.println("Ghost class (null input): " + ghost + " (expected null)");
        }

        System.err.println("=== Test complete — no crash ===");
    }
}
