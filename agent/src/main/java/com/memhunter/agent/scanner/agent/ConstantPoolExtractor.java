package com.memhunter.agent.scanner.agent;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Parses the CONSTANT_Utf8 entries from a Java class file's constant pool.
 * Pure function, no JVM/reflection dependency. Used to diff in-memory bytecode against
 * on-disk JAR bytecode and surface attacker-injected string constants.
 */
public final class ConstantPoolExtractor {

    private ConstantPoolExtractor() {}

    /** Returns all CONSTANT_Utf8 strings. Returns an empty set on null/garbage; never throws. */
    public static Set<String> utf8Constants(byte[] classBytes) {
        Set<String> out = new LinkedHashSet<>();
        if (classBytes == null || classBytes.length < 10) return out;
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(classBytes))) {
            in.readInt();            // magic 0xCAFEBABE
            in.readUnsignedShort();  // minor version
            in.readUnsignedShort();  // major version
            int cpCount = in.readUnsignedShort();
            for (int i = 1; i < cpCount; i++) {
                int tag = in.readUnsignedByte();
                switch (tag) {
                    case 1:  // CONSTANT_Utf8
                        out.add(in.readUTF());
                        break;
                    case 7: case 8: case 16: case 19: case 20:
                        // Class / String / MethodType / Module / Package: u2 index
                        in.readUnsignedShort();
                        break;
                    case 15: // MethodHandle: u1 + u2
                        in.readUnsignedByte();
                        in.readUnsignedShort();
                        break;
                    case 3: case 4: case 9: case 10: case 11: case 12: case 17: case 18:
                        // Integer/Float/Fieldref/Methodref/InterfaceMethodref/NameAndType/Dynamic/InvokeDynamic: u4
                        in.readInt();
                        break;
                    case 5: case 6: // Long / Double: u8, occupies TWO pool slots
                        in.readLong();
                        i++;
                        break;
                    default:
                        // Unknown tag: stop parsing, return what we have (best effort)
                        return out;
                }
            }
        } catch (Throwable ignored) {
            // Truncated/corrupt bytecode: return whatever was collected
        }
        return out;
    }
}
