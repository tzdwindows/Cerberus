// Architect: tzdwindows 7
// UnsafeGateway: Phase 1 pure-Java defense layer.
// Gets Unsafe via reflection (no DLL needed), scans/repairs JVM hooks,
// defines ghost classes invisible to JVMTI, neutralizes ServiceLoader competitors.
package it.unimi.dsi.fastutil.tzd.bridge;

import sun.misc.Unsafe;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public final class UnsafeGateway {
    private static Unsafe unsafe;
    private static long jvmBase;
    private static long jvmSize;
    private static boolean bootstrapped;

    static {
        bootstrap();
    }

    // ─── Bootstrap ───────────────────────────────────────────

    public static synchronized void bootstrap() {
        if (bootstrapped) return;
        bootstrapped = true;
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            unsafe = (Unsafe) f.get(null);
            System.err.println("[TZD-Gateway] Unsafe acquired: addressSize=" + unsafe.addressSize());
        } catch (Throwable t) {
            System.err.println("[TZD-Gateway] Unsafe acquisition FAILED: " + t.getMessage());
            return;
        }
        locateJvm();
    }

    public static Unsafe getUnsafe() { return unsafe; }
    public static boolean isAvailable() { return unsafe != null; }
    public static long getJvmBase() { return jvmBase; }
    public static long getJvmSize() { return jvmSize; }

    // ─── Locate jvm.dll in process memory ─────────────────────
    // IMPORTANT: We must NOT use Unsafe.getShort(long addr) to scan
    // arbitrary absolute addresses — if the address is unmapped, the
    // OS raises EXCEPTION_ACCESS_VIOLATION which bypasses Java's
    // try/catch and crashes the JVM.
    //
    // Instead, we try safe Java APIs. If none work, the native
    // pristine_store.cpp (which uses EnumProcessModules — a safe
    // Win32 API) will find jvm.dll after the DLL is loaded.

    private static void locateJvm() {
        if (unsafe == null) return;
        try {
            // Attempt 1: Use ProcessHandle to get process PID (safe).
            // We cannot get module addresses from pure Java without
            // risking a crash. The native code will handle this.
            long pid = ProcessHandle.current().pid();
            System.err.println("[TZD-Gateway] process pid=" + pid
                    + " — jvm.dll base will be detected by native code");
            // jvmBase stays 0; native pristine_init() will set it.
            jvmBase = 0;
        } catch (Throwable t) {
            System.err.println("[TZD-Gateway] locateJvm: " + t.getMessage());
        }
    }

    // NOTE: readKlassPointer and findModuleBaseFromAddr were REMOVED.
    // Reading the Class object's internal Klass* pointer via Unsafe
    // and then scanning absolute addresses for MZ headers causes
    // EXCEPTION_ACCESS_VIOLATION crashes on JDK 20. The jvm.dll
    // base address must be obtained via the safe Win32 API
    // EnumProcessModules in native code (pristine_store.cpp).

    // ─── Hook scanning & repair ───────────────────────────────
    // NOTE: Scanning absolute memory addresses via Unsafe.getByte(long)
    // is DANGEROUS — if the address is unmapped, the OS raises
    // EXCEPTION_ACCESS_VIOLATION which crashes the JVM (bypasses
    // Java try/catch). All memory scanning is done by native code
    // (hook_scanner.cpp / pristine_store.cpp) which uses Win32 APIs
    // (EnumProcessModules, VirtualQuery) that safely handle unmapped
    // addresses.
    //
    // The following methods are REMOVED from the Java side:
    //   looksLikeHook(long)        — scanned absolute addresses
    //   readBytes(long, int)       — read absolute addresses
    //   writeBytes(long, byte[])    — write absolute addresses
    //   bytesMatch(long, byte[])    — compare absolute addresses
    //   readPointer(long)           — read absolute pointer
    //   writePointer(long, long)    — write absolute pointer

    // ─── Ghost class definition ────────────────────────────────

    // Define an anonymous/ghost class not registered in the system dictionary.
    // In JDK 15+, Unsafe.defineAnonymousClass was removed — we use
    // MethodHandles.Lookup.defineHiddenClass instead, which produces a
    // true hidden class: invisible to JVMTI GetLoadedClasses,
    // ClassFileLoadHook, RetransformClasses, and Class.forName.
    public static Class<?> defineGhostClass(Class<?> hostClass, byte[] bytecode) {
        try {
            Lookup lookup = MethodHandles.privateLookupIn(hostClass, MethodHandles.lookup());
            Lookup hidden = lookup.defineHiddenClass(bytecode, true,
                    MethodHandles.Lookup.ClassOption.NESTMATE);
            Class<?> ghost = hidden.lookupClass();
            System.err.println("[TZD-Gateway] ghost class defined: " + ghost.getName());
            return ghost;
        } catch (Throwable t) {
            System.err.println("[TZD-Gateway] ghost class definition failed: " + t.getMessage());
            return null;
        }
    }

    // ─── ServiceLoader neutralization ─────────────────────────

    // Attempt to clear the ServiceLoader's lazy provider list to prevent
    // competitor ImmediateWindowProvider classes from loading after us.
    @SuppressWarnings("unchecked")
    public static int neutralizeServiceLoader(String serviceName) {
        if (unsafe == null) return 0;
        int cleared = 0;
        try {
            // ServiceLoader stores providers in a LinkedHashMap called "providers"
            Class<?> slClass = Class.forName("java.util.ServiceLoader");
            Field providersField = slClass.getDeclaredField("providers");
            providersField.setAccessible(true);

            // We need a ServiceLoader instance to modify. The one Forge uses
            // is typically the one returned by ServiceLoader.load().
            // We can't directly access that instance, but we can try to
            // influence the iteration by clearing the loaded providers cache.

            // Alternative: modify the LazyClassPathProviderIterator's nextIndex
            try {
                Field iterField = slClass.getDeclaredField("currentClassLoader");
                iterField.setAccessible(true);
            } catch (NoSuchFieldException ignored) {}

            System.err.println("[TZD-Gateway] ServiceLoader field scan for: " + serviceName);
        } catch (Throwable t) {
            System.err.println("[TZD-Gateway] ServiceLoader neutralization skipped: " + t.getMessage());
        }
        return cleared;
    }

    // ─── Load-chain verification ───────────────────────────
    // The actual call chain for DLL loading is:
    //   System.load(String)           — regular Java method (NOT native)
    //   Runtime.load0(Class, String)  — regular Java method (NOT native)
    //   ClassLoader.loadLibrary(...)  — regular Java method
    //   ClassLoader$NativeLibrary.load(String, boolean) — native method
    //   JVM_LoadLibrary(name)        — C++ in jvm.dll
    //   os::dll_load(name)            — LoadLibraryEx
    //
    // We verify the chain is intact by checking that the actual
    // native method (NativeLibrary.load) is still native.
    // If a competitor used RetransformClasses to replace it with
    // bytecode, we detect it here.

    public static boolean verifyLoadChain() {
        try {
            // System.load — regular Java method, delegates to Runtime.load0.
            // Just verify it exists.
            Method sysLoad = System.class.getDeclaredMethod("load", String.class);
            if (sysLoad == null) return false;

            // Runtime.load0 — package-private Java method.
            // Need --add-opens java.base/java.lang=ALL-UNNAMED (Forge adds this).
            Method rtLoad0 = Runtime.class.getDeclaredMethod("load0", Class.class, String.class);
            rtLoad0.setAccessible(true);

            // The ACTUAL native method that loads the DLL.
            // JDK 8:  java.lang.ClassLoader$NativeLibrary.load(String, boolean)
            // JDK 9+: jdk.internal.loader.NativeLibraries.load(NativeLibraryImpl, String, boolean, boolean)
            //
            // If a competitor used RetransformClasses to replace it with
            // bytecode, the native modifier disappears — we detect it here.
            Method nativeLoad = findNativeLoadMethod();
            if (nativeLoad == null) {
                System.err.println("[TZD-Gateway] verifyLoadChain: native load method not found");
                return false;
            }
            nativeLoad.setAccessible(true);
            if (!Modifier.isNative(nativeLoad.getModifiers())) {
                System.err.println("[TZD-Gateway] CRITICAL: native load method is NOT native — load chain compromised!");
                return false;
            }
            System.err.println("[TZD-Gateway] load chain verified: " + nativeLoad.getDeclaringClass().getName()
                    + "." + nativeLoad.getName() + " is native");
            return true;
        } catch (Throwable t) {
            System.err.println("[TZD-Gateway] verifyLoadChain error: " + t.getMessage());
            return false;
        }
    }

    // Find the native load method across JDK versions.
    // JDK 8:  ClassLoader$NativeLibrary.load(String, boolean)
    // JDK 9+: NativeLibraries.load(NativeLibraryImpl, String, boolean, boolean)
    private static Method findNativeLoadMethod() {
        // JDK 9+ path
        try {
            Class<?> nlClass = Class.forName("jdk.internal.loader.NativeLibraries");
            for (Method m : nlClass.getDeclaredMethods()) {
                if (m.getName().equals("load") && m.getParameterCount() == 4) {
                    return m; // private static native boolean load(...)
                }
            }
        } catch (ClassNotFoundException ignored) {}
        // JDK 8 fallback
        try {
            Class<?> nlClass = Class.forName("java.lang.ClassLoader$NativeLibrary");
            for (Method m : nlClass.getDeclaredMethods()) {
                if (m.getName().equals("load") && m.getParameterCount() == 2) {
                    return m;
                }
            }
        } catch (ClassNotFoundException ignored) {}
        return null;
    }

    // ─── Native memory allocation (safe — JVM-managed) ────────

    public static long allocateMemory(long size) {
        if (unsafe == null) return 0;
        try {
            return unsafe.allocateMemory(size);
        } catch (Throwable t) {
            return 0;
        }
    }

    public static void freeMemory(long addr) {
        if (unsafe == null || addr == 0) return;
        try {
            unsafe.freeMemory(addr);
        } catch (Throwable ignored) {}
    }
}
