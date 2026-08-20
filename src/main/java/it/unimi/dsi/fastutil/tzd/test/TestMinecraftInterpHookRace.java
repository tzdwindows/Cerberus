// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd.test;

import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Simulates Minecraft's C1/C2-inlined render and server getter paths. */
public final class TestMinecraftInterpHookRace {
    private static final int WORKERS = 6;
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

    private TestMinecraftInterpHookRace() {}

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
            if (health != 0.0f || foodLevel != 0 || saturation != 0.0f) {
                throw new AssertionError("hook state mismatch: " + health + ", " + foodLevel + ", " + saturation);
            }
        } else if (health != 20.0f || foodLevel != 20 || saturation != 5.0f) {
            throw new AssertionError("original state mismatch: " + health + ", " + foodLevel + ", " + saturation);
        }
    }

    public static void main(String[] args) throws Exception {
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        String dllPath = "F:/秒杀/aitest/seckill_mod/native/seckill_native.dll";
        try {
            System.load(dllPath);
        } catch (UnsatisfiedLinkError error) {
            if (!error.getMessage().contains("already loaded")) throw error;
        }
        NativeBridge.methodDetectOffsets0();
        if (!NativeBridge.interpHookInit0()) {
            throw new AssertionError("interpreter hook unavailable; launch with -agentpath:" + dllPath);
        }

        LivingEntityLike entity = new LivingEntityLike();
        FoodDataLike food = new FoodDataLike();
        Targets targets = new Targets();
        for (int i = 0; i < 2_000_000; i++) {
            sink = hotCaller(entity, food) + targets.getHealth() + targets.getFoodLevel() + targets.getSaturationLevel();
        }

        Method[] sources = {
                LivingEntityLike.class.getMethod("getHealth"),
                FoodDataLike.class.getMethod("getFoodLevel"),
                FoodDataLike.class.getMethod("getSaturationLevel")
        };
        Method[] targetMethods = {
                Targets.class.getMethod("getHealth"),
                Targets.class.getMethod("getFoodLevel"),
                Targets.class.getMethod("getSaturationLevel")
        };
        long[] sourcePtrs = new long[sources.length];
        for (int i = 0; i < sources.length; i++) sourcePtrs[i] = NativeBridge.methodPtrOf0(sources[i]);

        AtomicBoolean running = new AtomicBoolean(true);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch started = new CountDownLatch(WORKERS);
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < WORKERS; i++) {
            Thread thread = new Thread(() -> {
                started.countDown();
                try {
                    while (running.get()) {
                        float value = hotCaller(entity, food);
                        if (value < 0.0f || value > 2880.0f) throw new AssertionError("invalid transition result: " + value);
                        sink = value;
                    }
                } catch (Throwable t) {
                    failure.compareAndSet(null, t);
                    running.set(false);
                }
            }, "mc-render-server-sim-" + i);
            thread.start();
            threads.add(thread);
        }

        started.await();
        for (int cycle = 0; cycle < Integer.getInteger("hook.cycles", 100) && running.get(); cycle++) {
            for (int i = 0; i < sources.length; i++) {
                if (!NativeBridge.interpHookFreturn0(sourcePtrs[i], targetMethods[i])) {
                    throw new AssertionError("install failed at cycle " + cycle + ", method " + sources[i]);
                }
            }
            assertState(entity, food, true);
            for (long sourcePtr : sourcePtrs) {
                if (!NativeBridge.interpHookFreturnRemove0(sourcePtr)) {
                    throw new AssertionError("remove failed at cycle " + cycle);
                }
            }
            assertState(entity, food, false);
        }

        running.set(false);
        for (Thread thread : threads) thread.join();
        if (failure.get() != null) throw new AssertionError("worker failed", failure.get());
        System.out.println("PASS: health/food/saturation hot-switch race completed");
    }
}
