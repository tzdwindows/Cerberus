package it.unimi.dsi.fastutil.tzd.test;

import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import java.lang.reflect.Method;

/**
 * Quick verification test for the bytecode-patch + c2i deopt hook.
 * Short warmup (1000 iterations) — verifies the hook actually works.
 */
public final class QuickHookTest {
    public static class Entity {
        public float getHealth() { return 20.0f; }
        public int getFoodLevel() { return 20; }
        public float getSaturationLevel() { return 5.0f; }
    }
    public static class Targets {
        public float getHealth() { return 0.0f; }
        public int getFoodLevel() { return 0; }
        public float getSaturationLevel() { return 0.0f; }
    }

    public static void main(String[] args) throws Exception {
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        try { System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll"); }
        catch (UnsatisfiedLinkError e) { if (!e.getMessage().contains("already")) throw e; }

        NativeBridge.methodDetectOffsets0();
        NativeBridge.interpHookInit0();

        Entity e = new Entity();
        // Small warmup (enough to trigger C1 on simple methods)
        for (int i = 0; i < 1000; i++) {
            e.getHealth(); e.getFoodLevel(); e.getSaturationLevel();
        }

        System.err.println("=== BEFORE hook ===");
        System.err.println("health=" + e.getHealth() + " food=" + e.getFoodLevel()
                + " sat=" + e.getSaturationLevel());

        // Hook all three
        Method srcHealth = Entity.class.getMethod("getHealth");
        Method srcFood = Entity.class.getMethod("getFoodLevel");
        Method srcSat = Entity.class.getMethod("getSaturationLevel");
        Method tgtHealth = Targets.class.getMethod("getHealth");
        Method tgtFood = Targets.class.getMethod("getFoodLevel");
        Method tgtSat = Targets.class.getMethod("getSaturationLevel");

        long hPtr = NativeBridge.methodPtrOf0(srcHealth);
        long fPtr = NativeBridge.methodPtrOf0(srcFood);
        long sPtr = NativeBridge.methodPtrOf0(srcSat);

        boolean hOk = NativeBridge.interpHookFreturn0(hPtr, tgtHealth);
        boolean fOk = NativeBridge.interpHookFreturn0(fPtr, tgtFood);
        boolean sOk = NativeBridge.interpHookFreturn0(sPtr, tgtSat);

        System.err.println("hook installed: H=" + hOk + " F=" + fOk + " S=" + sOk);

        // Check values
        float health = e.getHealth();
        int food = e.getFoodLevel();
        float sat = e.getSaturationLevel();
        System.err.println("=== AFTER hook ===");
        System.err.println("health=" + health + " food=" + food + " sat=" + sat);

        boolean pass = (health == 0.0f && food == 0 && sat == 0.0f);
        System.err.println(pass ? "PASS: all values are 0" : "FAIL: values not 0!");

        // Remove hooks
        NativeBridge.interpHookFreturnRemove0(hPtr);
        NativeBridge.interpHookFreturnRemove0(fPtr);
        NativeBridge.interpHookFreturnRemove0(sPtr);

        // Check restored values
        float health2 = e.getHealth();
        int food2 = e.getFoodLevel();
        float sat2 = e.getSaturationLevel();
        System.err.println("=== AFTER remove ===");
        System.err.println("health=" + health2 + " food=" + food2 + " sat=" + sat2);

        boolean pass2 = (health2 == 20.0f && food2 == 20 && sat2 == 5.0f);
        System.err.println(pass2 ? "PASS: values restored" : "FAIL: values not restored!");

        if (pass && pass2) {
            System.out.println("ALL TESTS PASS");
            System.exit(0);
        } else {
            System.out.println("TESTS FAILED");
            System.exit(1);
        }
    }
}
