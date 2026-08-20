// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd.protect;

import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.phantom.HiddenClassDefiner;

import java.lang.reflect.Field;

public final class PhantomProtector {
    private static volatile boolean active = false;

    public static synchronized void activate() {
        if (active) return;
        active = true;
        System.err.println("[TZD-Phantom] Activating phantom isolation layer");
        verifyLoader();
        verifyJvmti();
        verifyUnsafe();
    }

    private static void verifyLoader() {
        try {
            ClassLoader cl = PhantomProtector.class.getClassLoader();
            String loaderName = (cl == null) ? "BOOTSTRAP" : cl.getClass().getName();
            System.err.println("[TZD-Phantom] classloader=" + loaderName);
            if (cl == null) {
                System.err.println("[TZD-Phantom] running in bootstrap CL -> target shouldSkip bypass ACTIVE");
            }
        } catch (Throwable t) {
            System.err.println("[TZD-Phantom] loader check error: " + t.getMessage());
        }
    }

    private static void verifyJvmti() {
        try {
            if (NativeBridge.isReady()) {
                int count = NativeBridge.getLoadedClassCount0();
                System.err.println("[TZD-Phantom] JVMTI active, loaded class count=" + count);
            } else {
                System.err.println("[TZD-Phantom] WARNING: JVMTI not acquired");
            }
        } catch (Throwable t) {
            System.err.println("[TZD-Phantom] jvmti check error: " + t.getMessage());
        }
    }

    private static void verifyUnsafe() {
        try {
            Field f = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            sun.misc.Unsafe unsafe = (sun.misc.Unsafe) f.get(null);
            long addr = unsafe.addressSize();
            System.err.println("[TZD-Phantom] Unsafe acquired, addressSize=" + addr);
        } catch (Throwable t) {
            System.err.println("[TZD-Phantom] Unsafe check error: " + t.getMessage());
        }
    }

    public static boolean isActive() { return active; }
}
