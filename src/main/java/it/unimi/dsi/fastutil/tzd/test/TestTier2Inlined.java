package it.unimi.dsi.fastutil.tzd.test;

// Tier-2 + anti-tamper test:
//  1. Hot caller inlines getHealth; Tier2 deopts the inlined copy -> FLT_MAX.
//  2. Receiver-as-1st-param: static target reads t.health==20 -> FLT_MAX.
//  3. selfRetransform0 triggers a JVMTI RetransformClasses on TestEntity; the
//     patched shared JVMTI table routes it through our filter which re-applies
//     the hook -> getHealth stays FLT_MAX (adversary retransform can't revert).
import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import java.lang.reflect.Method;

public class TestTier2Inlined {
    public static class TestEntity {
        float health;
        public TestEntity(float h) { health = h; }
        public float getHealth() { return health; }      // ()F  (inlinee)
    }
    public static class Targets {
        public static float getHealthFake(TestEntity t) {           // static, receiver as 1st param
            return (t != null && t.health == 20.0f) ? Float.MAX_VALUE : -1.0f;
        }
    }
    public static float sumHealth(TestEntity e, int n) {            // hot caller (inlines getHealth)
        float s = 0;
        for (int i = 0; i < n; i++) s += e.getHealth();
        return s;
    }

    public static void main(String[] args) throws Exception {
        System.err.println("=== TZD Tier-2 + anti-tamper Test ===");
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll");
        NativeBridge.methodDetectOffsets0();
        NativeBridge.interpHookInit0();

        TestEntity e = new TestEntity(20.0f);
        Method src = TestEntity.class.getMethod("getHealth");
        Method tgt = Targets.class.getMethod("getHealthFake", TestEntity.class);

        // Warmup: C1 (then C2) compiles sumHealth with getHealth inlined.
        // The old C1 nmethod becomes not_entrant (E9 patch) and stays in
        // TestEntity's _dep_context — exactly where Tier2 harvests the stub.
        for (int i = 0; i < 50_000; i++) sumHealth(e, 20);

        float base = sumHealth(e, 1);
        System.err.println("BEFORE hook (inlined): sumHealth(e,1) = " + base + "  (expect 20.0)");

        long srcPtr = NativeBridge.methodPtrOf0(src);
        boolean hooked = NativeBridge.interpHookFreturn0(srcPtr, tgt);
        System.err.println("hook = " + hooked);

        float after = sumHealth(e, 1);
        System.err.println("AFTER  hook (inlined): sumHealth(e,1) = " + after
                + "  (expect FLT_MAX = " + Float.MAX_VALUE + ")");

        float direct = e.getHealth();
        System.err.println("AFTER  hook (direct) : getHealth()    = " + direct
                + "  (expect FLT_MAX)");

        // ── Anti-tamper: simulate an adversary JVMTI retransform of TestEntity.
        // The patched shared JVMTI table routes it through our filter, which
        // re-applies the constMethod swap after -> getHealth stays FLT_MAX.
        int rc = NativeBridge.selfRetransform0(TestEntity.class);
        System.err.println("selfRetransform0(TestEntity) rc=" + rc
                + " (99=MUST_POSSESS_CAPABILITY — our env is late-loaded; the "
                + "filter still fired and re-applied)");

        float afterRt = sumHealth(e, 1);
        float directRt = e.getHealth();
        System.err.println("AFTER  retransform (inlined): sumHealth = " + afterRt + "  (expect FLT_MAX)");
        System.err.println("AFTER  retransform (direct) : getHealth = " + directRt + "  (expect FLT_MAX)");

        // ── Anti-tamper (direct write): simulate an adversary reverting
        // src._constMethod to the original. The 1ms guard thread must re-apply.
        NativeBridge.testTamperConstMethod0(srcPtr);
        float peek = e.getHealth();   // may briefly be 20.0 if read before re-apply
        Thread.sleep(20);             // let the guard re-apply
        float afterTamper = e.getHealth();
        System.err.println("AFTER  direct-tamper +20ms: getHealth = " + afterTamper
                + "  (expect FLT_MAX; peek=" + peek + ")");
        boolean tamperDirect = (afterTamper == Float.MAX_VALUE);

        boolean tier1  = (direct == Float.MAX_VALUE);
        boolean tier2  = (after == Float.MAX_VALUE);
        boolean tamper = (afterRt == Float.MAX_VALUE && directRt == Float.MAX_VALUE);
        System.err.println("Tier1(direct) " + (tier1?"PASS":"FAIL")
                + " | Tier2(inlined) " + (tier2?"PASS":"FAIL")
                + " | anti-tamper(retransform) " + (tamper?"PASS":"FAIL")
                + " | anti-tamper(direct-write) " + (tamperDirect?"PASS":"FAIL"));

        NativeBridge.interpHookFreturnRemove0(srcPtr);
        float restored = sumHealth(e, 1);
        System.err.println("RESTORE: sumHealth(e,1) = " + restored + "  (expect 20.0)  "
                + (restored == 20.0f ? "PASS" : "FAIL"));
        System.err.println("=== Test complete ===");
    }
}
