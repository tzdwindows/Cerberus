package it.unimi.dsi.fastutil.tzd.test;

// Test: replace getHealth() with a native function returning FLT_MAX
import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;

public class TestGetHealth {
    // A simple class with getHealth() — simulates LivingEntity.getHealth()
    public static class TestEntity {
        private float health;
        public TestEntity(float h) { health = h; }
        public float getHealth() { return health; }
    }

    public static void main(String[] args) throws Exception {
        System.err.println("=== TZD getHealth Replacement Test ===");

        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll");

        // Step 1: Detect Method* offsets
        NativeBridge.methodDetectOffsets0();

        // Step 2: Create a test entity with health = 20.0f
        TestEntity entity = new TestEntity(20.0f);

        // Step 3: Call getHealth BEFORE replacement
        float before = entity.getHealth();
        System.err.println("getHealth BEFORE: " + before + " (expected 20.0)");

        // Step 4: Get the replacement function pointer (index 0 = FLT_MAX)
        long funcPtr = NativeBridge.getReplacementFuncByIndex0(0);
        System.err.println("replacement func ptr: 0x" + Long.toHexString(funcPtr));

        // Step 5: Find getHealth method and redirect it
        long handle = NativeBridge.methodFind0(
            TestEntity.class, "getHealth", "()F");
        System.err.println("getHealth handle: " + handle);

        if (handle != 0 && funcPtr != 0) {
            // Redirect!
            boolean redirected = NativeBridge.methodRedirect0(handle, funcPtr);
            System.err.println("redirect result: " + redirected);

            if (redirected) {
                // Step 6: Call getHealth AFTER replacement
                // This should call our native function returning FLT_MAX
                try {
                    float after = entity.getHealth();
                    System.err.println("getHealth AFTER: " + after);
                    if (after != before) {
                        System.err.println("✅ METHOD REPLACEMENT WORKS! " + before + " -> " + after);
                    } else {
                        System.err.println("❌ method returned same value — redirect may not have taken effect");
                    }
                } catch (Throwable t) {
                    System.err.println("getHealth call crashed: " + t);
                    System.err.println("(calling convention mismatch — interpreter stack vs C ABI)");
                }

                // Step 7: Restore original
                boolean restored = NativeBridge.methodRestore0(handle);
                System.err.println("restore result: " + restored);

                // Step 8: Verify getHealth works after restore
                float afterRestore = entity.getHealth();
                System.err.println("getHealth AFTER RESTORE: " + afterRestore + " (expected 20.0)");
            }
        } else {
            System.err.println("FAILED: could not find method or get func ptr");
        }

        System.err.println("=== getHealth Test complete ===");
    }
}
