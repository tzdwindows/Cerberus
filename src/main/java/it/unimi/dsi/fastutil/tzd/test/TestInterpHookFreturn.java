package it.unimi.dsi.fastutil.tzd.test;

// Example / test: NativeBridge.interpHookFreturn0(srcMethodPtr, targetMethod)
// constMethod swap — src runs target's Java bytecodes. Receiver-as-first-param:
// the target is STATIC and its first declared parameter receives src's `this`.
//
// Run (standalone, JDK 20):
//   javac -cp build/manual-classes TestInterpHookFreturn.java
//   java --add-opens java.base/java.lang=ALL-UNNAMED \
//        --add-opens java.base/jdk.internal.loader=ALL-UNNAMED \
//        -cp build/manual-classes TestInterpHookFreturn
import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import java.lang.reflect.Method;

public class TestInterpHookFreturn {
    public static class TestEntity {
        float health;                                   // package-private so Targets can read
        public TestEntity(float h) { health = h; }
        public float getHealth() { return health; }      // ()F -> 20.0  (src)
    }
    // STATIC target; first declared param = the receiver. size_of_parameters
    // (1) matches src's this-only count, so the shared interpreter frame is
    // valid and `t` IS the receiver.
    public static class Targets {
        public static float getHealthFake(TestEntity t) {
            return (t != null && t.health == 20.0f) ? Float.MAX_VALUE : -1.0f;
        }
    }

    public static void main(String[] args) throws Exception {
        System.err.println("=== TZD interpHookFreturn0 (constMethod swap, receiver-as-1st-param) ===");
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll");
        NativeBridge.methodDetectOffsets0();
        NativeBridge.interpHookInit0();

        TestEntity e = new TestEntity(20.0f);
        Method src = TestEntity.class.getMethod("getHealth");
        Method tgt = Targets.class.getMethod("getHealthFake", TestEntity.class);  // static
        long srcPtr = NativeBridge.methodPtrOf0(src);
        System.err.println("src getHealth Method* = 0x" + Long.toHexString(srcPtr));

        float before = e.getHealth();
        System.err.println("BEFORE hook: getHealth() = " + before + "  (expect 20.0)");

        boolean hooked = NativeBridge.interpHookFreturn0(srcPtr, tgt);
        System.err.println("interpHookFreturn0 = " + hooked);

        float after = e.getHealth();
        System.err.println("AFTER  hook: getHealth() = " + after
                + "  (expect FLT_MAX = " + Float.MAX_VALUE + ")");
        // FLT_MAX here proves BOTH that the hook took effect AND that `t`
        // (the receiver, with t.health==20) was passed as the first parameter.
        boolean ok = (after == Float.MAX_VALUE);
        System.err.println(ok ? "PASS: receiver passed as first param + target bytecodes run"
                              : "FAIL: see [TZD] logs");

        NativeBridge.interpHookFreturnRemove0(srcPtr);
        float restored = e.getHealth();
        System.err.println("RESTORE: getHealth() = " + restored + "  (expect 20.0)  "
                + (restored == 20.0f ? "PASS" : "FAIL"));
        System.err.println("=== Test complete ===");
    }
}
