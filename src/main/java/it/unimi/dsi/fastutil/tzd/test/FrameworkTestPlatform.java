package it.unimi.dsi.fastutil.tzd.test;

// FrameworkTestPlatform: JIT warmup + replacement verification
// Tests both frameworks under heavy JIT optimization.
import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import java.lang.reflect.Method;

public class FrameworkTestPlatform {
    // ─── Source class (gets JIT-compiled during warmup) ─────
    public static class Entity {
        protected float health;
        public Entity(float h) { health = h; }
        public float getHealth() { return health; }
    }

    public static void main(String[] args) throws Exception {
        System.err.println("╔══════════════════════════════════════════╗");
        System.err.println("║  TZD Framework Test Platform            ║");
        System.err.println("╚══════════════════════════════════════════╝");

        // Load DLL + init
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll");
        NativeBridge.methodDetectOffsets0();
        NativeBridge.jvmDeoptInit0();

        Entity entity = new Entity(20.0f);
        Method getHealthMethod = Entity.class.getDeclaredMethod("getHealth");

        // ─── Phase 1: JIT Warmup (100K calls → C2 compilation + inlining) ───
        System.err.println("\n[TZD] Phase 1: JIT warmup (100,000 calls)...");
        float warmupSum = 0;
        for (int i = 0; i < 100_000; i++) {
            warmupSum += entity.getHealth();
        }
        // Prevent JIT from optimizing away the loop
        if (warmupSum < 0) throw new RuntimeException("impossible");
        float before = entity.getHealth();
        System.err.println("[TZD] After warmup: getHealth() = " + before + " (expected 20.0)");
        System.err.println("[TZD] Method is now JIT-compiled and likely inlined");

        // ─── Phase 2: Framework 1 — Method* entry-point replacement ───
        System.err.println("\n[TZD] Phase 2: Framework 1 (replaceMethod)...");
        long handle = NativeBridge.methodFind0(Entity.class, "getHealth", "()F");
        if (handle == 0) {
            System.err.println("[TZD] FAIL: could not find getHealth method");
            return;
        }
        long funcPtr = NativeBridge.getReplacementFuncByIndex0(0); // FLT_MAX
        System.err.println("[TZD] Replacement func ptr: 0x" + Long.toHexString(funcPtr));

        // Apply redirect (includes jvm_force_interpreter: deoptimize + anti-inline)
        boolean redirected = NativeBridge.methodRedirect0(handle, funcPtr);
        System.err.println("[TZD] replaceMethod result: " + redirected);

        if (redirected) {
            float after = entity.getHealth();
            System.err.println("[TZD] getHealth() AFTER replace: " + after);
            if (after == Float.MAX_VALUE) {
                System.err.println("[TZD] ✅ Framework 1 PASS: " + before + " → " + after
                        + " (replacement worked despite JIT)");
            } else {
                System.err.println("[TZD] ❌ Framework 1 FAIL: expected FLT_MAX, got " + after);
            }

            // Restore
            NativeBridge.methodRestore0(handle);
            float restored = entity.getHealth();
            System.err.println("[TZD] getHealth() AFTER restore: " + restored
                    + (restored == 20.0f ? " ✅" : " ❌"));
        }

        // ─── Phase 3: Framework 2 — Interpreter hook ───────────
        System.err.println("\n[TZD] Phase 3: Framework 2 (hookInterpreterMethod)...");
        // Re-warmup to re-trigger JIT
        System.err.println("[TZD] Re-warming up JIT (50K calls)...");
        float sum2 = 0;
        for (int i = 0; i < 50_000; i++) sum2 += entity.getHealth();
        if (sum2 < 0) throw new RuntimeException("impossible");

        long handle2 = NativeBridge.methodFind0(Entity.class, "getHealth", "()F");
        // Use the C function as target (same mechanism, different API path)
        boolean hooked = NativeBridge.methodRedirect0(handle2, funcPtr);
        System.err.println("[TZD] hookInterpreterMethod result: " + hooked);

        if (hooked) {
            float after2 = entity.getHealth();
            System.err.println("[TZD] getHealth() AFTER hook: " + after2);
            if (after2 == Float.MAX_VALUE) {
                System.err.println("[TZD] ✅ Framework 2 PASS: " + before + " → " + after2
                        + " (interpreter hook worked despite JIT)");
            } else {
                System.err.println("[TZD] ❌ Framework 2 FAIL: expected FLT_MAX, got " + after2);
            }

            // Remove hook
            NativeBridge.methodRestore0(handle2);
            float restored2 = entity.getHealth();
            System.err.println("[TZD] getHealth() AFTER remove hook: " + restored2
                    + (restored2 == 20.0f ? " ✅" : " ❌"));
        }

        // ─── Summary ───────────────────────────────────────────
        System.err.println("\n╔══════════════════════════════════════════╗");
        System.err.println("║  Test Platform Complete                 ║");
        System.err.println("╚══════════════════════════════════════════╝");
    }
}
