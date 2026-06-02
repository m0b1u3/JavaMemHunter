package fixtures;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/** Test fixture: a ClassFileTransformer NOT in com.memhunter.* — should be flagged by TransformerScanner. */
public class EvilTransformer implements ClassFileTransformer {
    public byte[] transform(ClassLoader l, String n, Class<?> c, ProtectionDomain pd, byte[] b) {
        return null;
    }
}
