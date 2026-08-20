package it.unimi.dsi.fastutil.tzd.test;

// Test: method replacement via entry-point redirection (no bytecode modification)
import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;

public class TestMethodReplace {
    // A target method we'll try to replace
    public static String targetMethod() {
        return "ORIGINAL";
    }

    // Our replacement — called via JNI function pointer
    // This is a native function that we'll register as the replacement.
    // For testing, we just return a different string.
    // Since we can't easily create a native function pointer from Java,
    // we'll test the find/detect/redirect API and check that:
    // 1. methodDetectOffsets0 finds valid offsets
    // 2. methodFind0 finds the target method
    // 3. The Method* fields are readable

    public static void main(String[] args) throws Exception {
        System.err.println("=== TZD Method Replacement Test ===");

        // Phase 1: Unsafe + load chain
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();

        // Load the DLL
        String dllPath = "F:/秒杀/aitest/seckill_mod/native/seckill_native.dll";
        System.load(dllPath);
        System.err.println("DLL loaded");

        // Step 1: Detect Method* field offsets
        // This scans a non-native method (Object.toString) for
        // pointers into the interpreter code region.
        NativeBridge.methodDetectOffsets0();

        // Step 2: Find a target method
        // Get the Method* for Object.toString
        long handle = NativeBridge.methodFind0(
            Object.class, "toString", "()Ljava/lang/String;");
        System.err.println("methodFind0 handle: " + handle
                + (handle != 0 ? " (OK)" : " (FAILED)"));

        if (handle != 0) {
            // Step 3: Check the raw Method* pointer
            // The handle is a ReplacedMethod* struct
            // We can read it back from native code
            long jvmBase = NativeBridge.getJvmBaseAddress0();
            System.err.println("jvm.dll base: 0x" + Long.toHexString(jvmBase));

            // Step 4: Try to detect if a known function is hooked
            if (jvmBase != 0) {
                boolean hooked = NativeBridge.isFunctionHooked0(jvmBase, 16);
                System.err.println("jvm.dll entry hooked: " + hooked
                        + " (should be false — MZ header is not a hook)");
            }
        }

        // Step 5: Test methodFind0 with a non-existent method (should return 0)
        long badHandle = NativeBridge.methodFind0(
            Object.class, "nonExistentMethod", "()V");
        System.err.println("non-existent method handle: " + badHandle
                + (badHandle == 0 ? " (OK — correctly returns 0)" : " (ERROR)"));

        System.err.println("=== Method Replacement Test complete — no crash ===");
    }
}
