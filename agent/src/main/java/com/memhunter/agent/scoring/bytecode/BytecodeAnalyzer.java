package com.memhunter.agent.scoring.bytecode;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.HashSet;
import java.util.Set;

/**
 * ASM ClassVisitor that collects all INVOKE* method calls' owner#name pairs into a Set.
 * Handles both regular invokes (INVOKEVIRTUAL/STATIC/SPECIAL/INTERFACE) and INVOKEDYNAMIC
 * (extracting bootstrap method handles, which is how JDK 9+ lambdas reach their bodies).
 */
public class BytecodeAnalyzer extends ClassVisitor {

    private static final int ASM_API = Opcodes.ASM9;

    private final Set<String> methodCalls = new HashSet<>();

    public BytecodeAnalyzer() {
        super(ASM_API);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {
        return new MethodVisitor(ASM_API) {
            @Override
            public void visitMethodInsn(int opcode, String owner, String mname,
                                        String desc, boolean isInterface) {
                methodCalls.add(owner + "#" + mname);
            }

            @Override
            public void visitInvokeDynamicInsn(String name, String descriptor,
                                                Handle bootstrap, Object... bootstrapArgs) {
                // bootstrapArgs typically contain Handle references for lambda body / method ref
                for (Object arg : bootstrapArgs) {
                    if (arg instanceof Handle) {
                        Handle h = (Handle) arg;
                        methodCalls.add(h.getOwner() + "#" + h.getName());
                    }
                }
            }
        };
    }

    public BytecodeAnalysis toAnalysis() {
        return new BytecodeAnalysis(methodCalls);
    }
}
