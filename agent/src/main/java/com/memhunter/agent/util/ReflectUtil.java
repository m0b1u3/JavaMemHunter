package com.memhunter.agent.util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Optional;

public final class ReflectUtil {

    private ReflectUtil() {}

    public static Optional<Object> tryReadField(Object target, String fieldName) {
        if (target == null || fieldName == null) return Optional.empty();
        Class<?> c = target.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(fieldName);
                f.setAccessible(true);
                return Optional.ofNullable(f.get(target));
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            } catch (Throwable t) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    public static Optional<Object> tryReadAnyOf(Object target, String... fieldNames) {
        if (target == null || fieldNames == null) return Optional.empty();
        for (String name : fieldNames) {
            Optional<Object> v = tryReadField(target, name);
            if (v.isPresent()) return v;
        }
        return Optional.empty();
    }

    public static void setField(Object target, String fieldName, Object value) {
        if (target == null || fieldName == null) {
            throw new RuntimeException("setField: null target or fieldName");
        }
        Class<?> c = target.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(fieldName);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException ignored) {
                c = c.getSuperclass();
            } catch (Throwable t) {
                throw new RuntimeException("setField failed: " + fieldName, t);
            }
        }
        throw new RuntimeException("field not found: " + fieldName);
    }

    public static Optional<Object> tryInvoke(Object target, String methodName) {
        if (target == null || methodName == null) return Optional.empty();
        Class<?> c = target.getClass();
        while (c != null) {
            try {
                Method m = c.getDeclaredMethod(methodName);
                m.setAccessible(true);
                return Optional.ofNullable(m.invoke(target));
            } catch (NoSuchMethodException e) {
                c = c.getSuperclass();
            } catch (Throwable t) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }
}
