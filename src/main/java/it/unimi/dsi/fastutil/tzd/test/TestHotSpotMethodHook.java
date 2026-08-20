// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd.test;

import it.unimi.dsi.fastutil.tzd.SekKillMod;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

public final class TestHotSpotMethodHook {
    private static final int THREADS = 8;
    private static final int TOGGLES = 2_000_000;

    private TestHotSpotMethodHook() {
    }

    public static void main(String[] args) throws Exception {
        AtomicBoolean active = new AtomicBoolean(false);
        AtomicBoolean running = new AtomicBoolean(true);
        CountDownLatch started = new CountDownLatch(THREADS);
        List<Thread> workers = new ArrayList<>();

        for (int i = 0; i < THREADS; i++) {
            Thread worker = new Thread(() -> {
                started.countDown();
                while (running.get()) {
                    float value = SekKillMod.hookHealth(active.get() ? 0.0f : 7.0f);
                    if (value != 0.0f && value != 7.0f) {
                        throw new AssertionError("state branch returned " + value);
                    }
                }
            }, "method-hook-stress-" + i);
            worker.start();
            workers.add(worker);
        }

        started.await();
        for (int i = 0; i < TOGGLES; i++) {
            active.set(!active.get());
        }

        running.set(false);
        for (Thread worker : workers) {
            worker.join();
        }
        System.out.println("PASS: state-only hook switching survived concurrent calls");
    }
}
