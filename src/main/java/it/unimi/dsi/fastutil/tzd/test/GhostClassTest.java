package it.unimi.dsi.fastutil.tzd.test;

import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import java.io.InputStream;
import java.lang.reflect.Method;

public final class GhostClassTest {

    private static byte[] readClassBytes(String className) throws Exception {
        String path = "/" + className.replace('.', '/') + ".class";
        try (InputStream in = GhostClassTest.class.getResourceAsStream(path)) {
            if (in == null) throw new RuntimeException("Class not found: " + path);
            return in.readAllBytes();
        }
    }

    private static void testGhost(String label, byte[] bytes, Class<?> hostClass) {
        System.out.println("\n=== " + label + " ===");
        Class<?> ghost = null;
        try {
            ghost = NativeBridge.defineGhostClass0(bytes, hostClass);
        } catch (Throwable t) {
            System.out.println("FAIL: defineGhostClass0 threw: " + t);
            t.printStackTrace();
            return;
        }
        if (ghost == null) { System.out.println("FAIL: returned null"); return; }
        System.out.println("Returned: " + ghost);

        // Test 1: Unsafe.allocateInstance first (no cached accessor, reads IK directly)
        Object instance = null;
        try {
            java.lang.reflect.Field f = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            sun.misc.Unsafe unsafe = (sun.misc.Unsafe) f.get(null);
            instance = unsafe.allocateInstance(ghost);
            System.out.println("[new] Unsafe.allocateInstance: " + instance);
        } catch (Throwable t) { System.out.println("[new] Unsafe FAIL: " + t); }

        // Test 1b: Constructor.newInstance (may use cached accessor)
        try {
            Object newInstance = ghost.getDeclaredConstructor().newInstance();
            System.out.println("[new] Constructor.newInstance: " + newInstance);
        } catch (Throwable t) { System.out.println("[new] Constructor FAIL: " + t); }

        // Test 2: Reflection Method.invoke (the "can't reflect" problem)
        if (instance != null) {
            try {
                Method m = ghost.getDeclaredMethod("getValue");
                m.setAccessible(true);
                float val = (float) m.invoke(instance);
                System.out.println("[reflect] getValue() = " + val + " (expect 42.0) " + (val == 42.0f ? "PASS" : "FAIL"));
            } catch (Throwable t) { System.out.println("[reflect] FAIL: " + t); t.printStackTrace(); }
        }

        // Test 3: getDeclaredFields
        try {
            var fields = ghost.getDeclaredFields();
            System.out.println("[reflect] getDeclaredFields: " + fields.length + " fields " + (fields.length > 0 ? "PASS" : "FAIL"));
        } catch (Throwable t) { System.out.println("[reflect] getDeclaredFields FAIL: " + t); }

        // Test 4: getDeclaredMethods
        try {
            var methods = ghost.getDeclaredMethods();
            System.out.print("[reflect] getDeclaredMethods: " + methods.length + " methods:");
            for (var m : methods) System.out.print(" " + m.getName());
            System.out.println(methods.length > 0 ? " PASS" : " FAIL");
        } catch (Throwable t) { System.out.println("[reflect] getDeclaredMethods FAIL: " + t); }

        // Test visibility
        try {
            Class.forName("it.unimi.dsi.fastutil.tzd.test.QuickProtectTest$SecretClass");
            System.out.println("Visibility: original found");
        } catch (ClassNotFoundException e) { System.out.println("Visibility: invisible"); }

        // Test protection status
        try { System.out.println(NativeBridge.debugCheckProtection0(ghost)); }
        catch (Throwable t) { System.out.println("Debug error: " + t.getMessage()); }

        System.out.println("Name: " + ghost.getName());
    }

    public static void main(String[] args) throws Exception {
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        try { System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll"); }
        catch (UnsatisfiedLinkError e) { if (!e.getMessage().contains("already")) throw e; }
        NativeBridge.methodDetectOffsets0();
        NativeBridge.interpHookInit0();

        // ── Warm up string concat bootstrap BEFORE defining ghost class ──
        // IMPL_LOOKUP uses Object.class as its lookupClass. After we redirect
        // Object.class's _klass to our clone IK, resolve_MemberName uses the
        // clone IK as the caller for access checks, which fails.
        // By warming up the bootstrap here, the CallSite for string concat
        // is cached BEFORE the modification. Subsequent string concatenations
        // use the cached MethodHandle (no new bootstrap → no re-resolution).
        String warmup = "" + new Object() + " test";
        System.err.println("[warmup] " + warmup);

        byte[] bytes = readClassBytes("it.unimi.dsi.fastutil.tzd.test.QuickProtectTest$SecretClass");
        System.out.println("Read " + bytes.length + " bytes of class data");

        //// Test 1: hostClass provided (mode A)
        //testGhost("Test 1: hostClass = GhostClassTest.class", bytes, GhostClassTest.class);
//
        //// Test 2: hostClass = null (mode B — walk CLD list, no FindClass)
        //testGhost("Test 2: hostClass = null (CLD walk)", bytes, null);

        // Test 3: Mode C — class NOT on classpath
        // Modify class name in bytecodes: "SecretClass" -> "GhostSecret" (same length)
        byte[] ghostBytes = bytes.clone();
        String oldName = "SecretClass";
        String newName = "GhostSecret";
        // Search for the UTF8 string in bytecodes and replace
        boolean replaced = false;
        for (int i = 0; i < ghostBytes.length - oldName.length(); i++) {
            boolean match = true;
            for (int j = 0; j < oldName.length(); j++) {
                if ((char) ghostBytes[i + j] != oldName.charAt(j)) { match = false; break; }
            }
            if (match) {
                for (int j = 0; j < newName.length(); j++) {
                    ghostBytes[i + j] = (byte) newName.charAt(j);
                }
                replaced = true;
                break; // only replace first occurrence
            }
        }
        System.out.println("\n=== Test 3: hostClass = null, class NOT on classpath (Mode C) ===");
        System.out.println("Class name modified: " + replaced);
        if (replaced) {
            testGhost("Test 3: hostClass = null (create from scratch)", ghostBytes, null);
        }

        System.out.println("\n=== Done ===");
        System.exit(0);
    }
}
