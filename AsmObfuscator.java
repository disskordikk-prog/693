package puzo.pushka.converter;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;

public final class AsmObfuscator {
    private static final String DECRYPT_OWNER = "puzo/pushka/runtime/StringObf";
    private static final String DECRYPT_NAME = "d";
    private static final String DECRYPT_DESC = "(Ljava/lang/String;)Ljava/lang/String;";

    private static final SecureRandom RNG = new SecureRandom();

    private AsmObfuscator() {
    }

    public static byte[] obfuscateJar(byte[] jarBytes) throws IOException {
        if (jarBytes == null || jarBytes.length == 0) {
            return jarBytes;
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream(jarBytes.length);
        try (JarInputStream jis = new JarInputStream(new ByteArrayInputStream(jarBytes));
             JarOutputStream jos = new JarOutputStream(baos)) {
            JarEntry entry;
            while ((entry = jis.getNextJarEntry()) != null) {
                if (entry.isDirectory()) {
                    JarEntry outDir = new JarEntry(entry.getName());
                    jos.putNextEntry(outDir);
                    jos.closeEntry();
                    continue;
                }
                byte[] data = jis.readAllBytes();
                byte[] out = data;
                String name = entry.getName();
                if (name.endsWith(".class")) {
                    out = obfuscateClass(data);
                }
                JarEntry outEntry = new JarEntry(name);
                jos.putNextEntry(outEntry);
                jos.write(out);
                jos.closeEntry();
            }
        }
        return baos.toByteArray();
    }

    private static byte[] obfuscateClass(byte[] classBytes) {
        try {
            ClassReader cr = new ClassReader(classBytes);
            ClassNode cn = new ClassNode();
            cr.accept(cn, 0);

            cn.sourceFile = null;
            cn.sourceDebug = null;

            for (MethodNode method : cn.methods) {
                if (method.localVariables != null) {
                    method.localVariables.clear();
                }
                if (method.parameters != null) {
                    method.parameters.clear();
                }
                if (method.instructions == null) {
                    continue;
                }

                AbstractInsnNode insn = method.instructions.getFirst();
                while (insn != null) {
                    AbstractInsnNode next = insn.getNext();
                    if (insn instanceof LineNumberNode) {
                        method.instructions.remove(insn);
                    } else if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String) {
                        String value = (String) ldc.cst;
                        String enc = encryptString(value);
                        InsnList replacement = new InsnList();
                        replacement.add(new LdcInsnNode(enc));
                        replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, DECRYPT_OWNER, DECRYPT_NAME, DECRYPT_DESC, false));
                        method.instructions.insert(insn, replacement);
                        method.instructions.remove(insn);
                    }
                    insn = next;
                }
            }

            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            cn.accept(cw);
            return cw.toByteArray();
        } catch (Throwable t) {
            return classBytes;
        }
    }

    private static String encryptString(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        byte[] key = puzo.pushka.runtime.BuildKey.get();
        byte[] plain = value.getBytes(StandardCharsets.UTF_8);
        int seed = RNG.nextInt(256);
        byte[] out = new byte[plain.length + 1];
        out[0] = (byte) seed;
        for (int i = 0; i < plain.length; i++) {
            int k = key[(i + seed) % key.length] & 0xFF;
            out[i + 1] = (byte) (plain[i] ^ k ^ seed);
        }
        return Base64.getEncoder().encodeToString(out);
    }
}
