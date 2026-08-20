package it.unimi.dsi.fastutil.tzd.test;

import it.unimi.dsi.fastutil.tzd.bridge.NativeBridge;
import it.unimi.dsi.fastutil.tzd.bridge.UnsafeGateway;

import java.lang.reflect.Method;

public class TestDispatchHook {
    public static class TestEntity {
        String secret;
        public TestEntity(String s) { secret = s; }
        public String getSecret() { return secret; }      // ()Ljava/lang/String; -> "Original Pristine Secret" (src)
    }

    public static class Targets {
        // 静态、无参、返回 String。
        // Dispatch Hook 会在安装时调用一次此方法，捕获其返回的 String 引用，并在 Stub 中固化该常数。
        // 之后从 Stub 运行时不会再发生对该方法的调用。
        public static String getSecretFake() {
            System.out.println("getSecretFake() invoked");
            return "Hooked Secret Value!";
        }
    }

    public static void main(String[] args) throws Exception {
        System.err.println("=== TZD dispatch-hook (real interpreter hook, variant b) String Test ===");
        UnsafeGateway.bootstrap();
        UnsafeGateway.verifyLoadChain();
        System.load("F:/秒杀/aitest/seckill_mod/native/seckill_native.dll");
        NativeBridge.methodDetectOffsets0();
        NativeBridge.dispatchHookInit0();

        TestEntity e = new TestEntity("Original Pristine Secret");
        Method src = TestEntity.class.getMethod("getSecret");
        Method tgt = Targets.class.getMethod("getSecretFake");   // static, no params

        long srcPtr = NativeBridge.methodPtrOf0(src);
        System.err.println("src getSecret Method* = 0x" + Long.toHexString(srcPtr));

        // 1. 验证 Hook 前的状态
        String before = e.getSecret();
        System.err.println("BEFORE hook: getSecret = \"" + before + "\"  (expect \"Original Pristine Secret\")");

        // 2. 施加 Hook (由于是 String 引用类型，底层会路由至带有对应指针常数的字节码 Stub 机制)
        boolean dh = NativeBridge.dispatchHookFreturn0(srcPtr, tgt);
        System.err.println("dispatchHookFreturn0 = " + dh);

        // 3. 验证 Hook 后的状态
        String after = e.getSecret();
        System.err.println("AFTER  hook: getSecret = \"" + after + "\"");
        System.err.println("Validation: " + ("Hooked Secret Value!".equals(after) ? "PASS" : "FAIL"));

        // 4. 解除 Hook 并验证恢复状态
        NativeBridge.dispatchHookFreturnRemove0(srcPtr);
        String restored = e.getSecret();
        System.err.println("RESTORE: getSecret = \"" + restored + "\"");
        System.err.println("Validation: " + ("Original Pristine Secret".equals(restored) ? "PASS" : "FAIL"));

        System.err.println("=== Test complete ===");
    }
}