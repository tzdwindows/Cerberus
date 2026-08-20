package it.unimi.dsi.fastutil.tzd.test;

import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.CountDownLatch;
import java.util.ArrayList;
import java.util.List;

/** Same as TestMinecraftInterpHookRace but with 100K warmup (vs 2M). */
public final class FastRaceTest {
    private static final int WORKERS = 4;
    private static volatile float sink;

    public static class LivingEntityLike {
        public float getHealth() { return 20.0f; }
    }
    public static class FoodDataLike {
        public int getFoodLevel() { return 20; }
        public float getSaturationLevel() { return 5.0f; }
    }
    public static class Targets {
        public float getHealth() { return 0.0f; }
        public int getFoodLevel() { return 0; }
        public float getSaturationLevel() { return 0.0f; }
    }

    private static float hotCaller(LivingEntityLike entity, FoodDataLike food) {
        float total = 0.0f;
        for (int i = 0; i < 64; i++) {
            total += entity.getHealth();
            total += food.getFoodLevel();
            total += food.getSaturationLevel();
        }
        return total;
    }

    private static void assertState(LivingEntityLike entity, FoodDataLike food, boolean hooked) {
        float health = entity.getHealth();
        int foodLevel = food.getFoodLevel();
        float saturation = food.getSaturationLevel();
        if (hooked) {
            if (health != 0.0f || foodLevel != 0 || saturation != 0.0f)
                throw new AssertionError("hook mismatch: " + health + ", " + foodLevel + ", " + saturation);
        } else if (health != 20.0f || foodLevel != 20 || saturation != 5.0f)
            throw new AssertionError("orig mismatch: " + health + ", " + foodLevel + ", " + saturation);
    }

    public static void main(String[] args) throws Exception {
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        try { System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll"); }
        catch (UnsatisfiedLinkError e) { if (!e.getMessage().contains("already")) throw e; }
        NativeBridge.methodDetectOffsets0();
        NativeBridge.interpHookInit0();

        LivingEntityLike entity = new LivingEntityLike();
        FoodDataLike food = new FoodDataLike();
        Targets targets = new Targets();
        // Reduced warmup: 100K (enough for C1, fast)
        for (int i = 0; i < 100_000; i++) {
            sink = hotCaller(entity, food) + targets.getHealth();
        }

        Method[] sources = {
            LivingEntityLike.class.getMethod("getHealth"),
            FoodDataLike.class.getMethod("getFoodLevel"),
            FoodDataLike.class.getMethod("getSaturationLevel")
        };
        Method[] tgts = {
            Targets.class.getMethod("getHealth"),
            Targets.class.getMethod("getFoodLevel"),
            Targets.class.getMethod("getSaturationLevel")
        };
        long[] ptrs = new long[sources.length];
        for (int i = 0; i < sources.length; i++) ptrs[i] = NativeBridge.methodPtrOf0(sources[i]);

        AtomicBoolean running = new AtomicBoolean(true);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch started = new CountDownLatch(WORKERS);
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < WORKERS; i++) {
            Thread t = new Thread(() -> {
                started.countDown();
                try {
                    while (running.get()) {
                        float v = hotCaller(entity, food);
                        if (v < 0.0f || v > 2880.0f) throw new AssertionError("invalid: " + v);
                        sink = v;
                    }
                } catch (Throwable t2) {
                    failure.compareAndSet(null, t2);
                    running.set(false);
                }
            }, "worker-" + i);
            t.start();
            threads.add(t);
        }

        started.await();
        int cycles = Integer.getInteger("hook.cycles", 10);
        for (int cycle = 0; cycle < cycles && running.get(); cycle++) {
            for (int i = 0; i < sources.length; i++)
                NativeBridge.interpHookFreturn0(ptrs[i], tgts[i]);
            assertState(entity, food, true);
            for (long p : ptrs) NativeBridge.interpHookFreturnRemove0(p);
            assertState(entity, food, false);
        }

        running.set(false);
        for (Thread t : threads) t.join();
        if (failure.get() != null) throw new AssertionError("worker failed", failure.get());
        System.out.println("PASS: race test completed (" + cycles + " cycles)");
    }
}
