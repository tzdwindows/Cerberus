// Architect: tzdwindows 7
package it.unimi.dsi.fastutil.tzd.phantom;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.invoke.MethodType;

public final class HiddenClassDefiner {
    static {
        System.err.println("[TZD-Phantom] HiddenClassDefiner ready");
    }

    public static Class<?> defineHidden(byte[] bytecode) {
        try {
            Lookup lookup = MethodHandles.privateLookupIn(HiddenClassDefiner.class, MethodHandles.lookup());
            Lookup hidden = lookup.defineHiddenClass(bytecode, true, MethodHandles.Lookup.ClassOption.NESTMATE);
            Class<?> cls = hidden.lookupClass();
            System.err.println("[TZD-Phantom] hidden class defined: " + cls.getName());
            return cls;
        } catch (Throwable t) {
            System.err.println("[TZD-Phantom] defineHidden failed: " + t.getMessage());
            return null;
        }
    }

    public static Object invokeHidden(Class<?> cls, String method, Class<?>[] params, Object[] args) {
        if (cls == null) return null;
        try {
            Lookup lookup = MethodHandles.privateLookupIn(cls, MethodHandles.lookup());
            return lookup.findStatic(cls, method, MethodType.methodType(void.class, params)).invokeWithArguments(args);
        } catch (Throwable t) {
            System.err.println("[TZD-Phantom] invokeHidden failed: " + t.getMessage());
            return null;
        }
    }
}
