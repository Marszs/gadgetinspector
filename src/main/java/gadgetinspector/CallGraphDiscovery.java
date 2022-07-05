package gadgetinspector;

import gadgetinspector.config.GIConfig;
import gadgetinspector.config.JavaDeserializationConfig;
import gadgetinspector.data.*;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.JSRInlinerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CallGraphDiscovery {
    private static final Logger LOGGER = LoggerFactory.getLogger(CallGraphDiscovery.class);

    private final Set<GraphCall> discoveredCalls = new HashSet<>();

    public void discover(final ClassResourceEnumerator classResourceEnumerator, GIConfig config) throws IOException {
        // 加载之前几个阶段全量收集到的信息，包括方法、类、继承关系、方法入参和返回值之间的污点分析结果
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        Map<ClassReference.Handle, ClassReference> classMap = DataLoader.loadClasses();
        InheritanceMap inheritanceMap = InheritanceMap.load();
        Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = PassthroughDiscovery.load();

        SerializableDecider serializableDecider = config.getSerializableDecider(methodMap, inheritanceMap);

        // 遍历所有的类
        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(in);
                try {
                    // 继续使用访问者模式，用到了一个新的Visitor: ModelGeneratorVisitor
                    cr.accept(new ModelGeneratorClassVisitor(classMap, inheritanceMap, passthroughDataflow, serializableDecider, Opcodes.ASM6),
                            ClassReader.EXPAND_FRAMES);
                } catch (Exception e) {
                    LOGGER.error("Error analyzing: " + classResource.getName(), e);
                }
            }
        }
    }

    public void save() throws IOException {
        DataLoader.saveData(Paths.get("callgraph.dat"), new GraphCall.Factory(), discoveredCalls);
    }

    private class ModelGeneratorClassVisitor extends ClassVisitor {

        private final Map<ClassReference.Handle, ClassReference> classMap;
        private final InheritanceMap inheritanceMap;
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        private final SerializableDecider serializableDecider;

        public ModelGeneratorClassVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                          InheritanceMap inheritanceMap,
                                          Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                          SerializableDecider serializableDecider, int api) {
            super(api);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDecider;
        }

        private String name;
        private String signature;
        private String superName;
        private String[] interfaces;

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.name = name;
            this.signature = signature;
            this.superName = superName;
            this.interfaces = interfaces;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
            // 核心MethodVisitor是ModelGeneratorMethodVisitor
            ModelGeneratorMethodVisitor modelGeneratorMethodVisitor = new ModelGeneratorMethodVisitor(classMap,
                    inheritanceMap, passthroughDataflow, serializableDecider, api, mv, this.name, access, name, desc, signature, exceptions);

            return new JSRInlinerAdapter(modelGeneratorMethodVisitor, access, name, desc, signature, exceptions);
        }

        @Override
        public void visitOuterClass(String owner, String name, String desc) {
            // TODO: Write some tests to make sure we can ignore this
            super.visitOuterClass(owner, name, desc);
        }

        @Override
        public void visitInnerClass(String name, String outerName, String innerName, int access) {
            // TODO: Write some tests to make sure we can ignore this
            super.visitInnerClass(name, outerName, innerName, access);
        }

        @Override
        public void visitEnd() {
            super.visitEnd();
        }
    }

    private class ModelGeneratorMethodVisitor extends TaintTrackingMethodVisitor<String> {

        private final Map<ClassReference.Handle, ClassReference> classMap;
        private final InheritanceMap inheritanceMap;
        private final SerializableDecider serializableDecider;
        private final String owner;
        private final int access;
        private final String name;
        private final String desc;

        public ModelGeneratorMethodVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                           InheritanceMap inheritanceMap,
                                           Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                           SerializableDecider serializableDecider, final int api, final MethodVisitor mv,
                                           final String owner, int access, String name, String desc, String signature,
                                           String[] exceptions) {
            super(inheritanceMap, passthroughDataflow, api, mv, owner, access, name, desc, signature, exceptions);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.serializableDecider = serializableDecider;
            this.owner = owner;
            this.access = access;
            this.name = name;
            this.desc = desc;
        }

        @Override
        public void visitCode() {
            super.visitCode();

            int localIndex = 0;
            int argIndex = 0;
            // 判断声明的方法是否是static方法
            if ((this.access & Opcodes.ACC_STATIC) == 0) {
                // 如果不是，那么就在局部变量表中添加"arg0"，表示当前的对象引用this
                setLocalTaint(localIndex, "arg" + argIndex);
                localIndex += 1;
                argIndex += 1;
            }
            // 然后根据方法的参数，依次向局部变量表中添加"arg1", "arg2"...
            for (Type argType : Type.getArgumentTypes(desc)) {
                setLocalTaint(localIndex, "arg" + argIndex);
                localIndex += argType.getSize();    // localIndex根据参数类型占用的size递增
                argIndex += 1;
            }
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String desc) {

            switch (opcode) {
                // 静态成员的读写不做处理
                case Opcodes.GETSTATIC:
                    break;
                case Opcodes.PUTSTATIC:
                    break;
                case Opcodes.GETFIELD:
                    Type type = Type.getType(desc);
                    // 只有参数类型所占size=1的时候，才进入then branch
                    if (type.getSize() == 1) {
                        Boolean isTransient = null;  // 表示变量是否被transient修饰

                        // If a field type could not possibly be serialized, it's effectively transient
                        if (!couldBeSerialized(serializableDecider, inheritanceMap, new ClassReference.Handle(type.getInternalName()))) {
                            // 判断该字段是否可以通过serializableDecider的决策, 如果不能, 依然把它当做是一个transient成员变量
                            isTransient = Boolean.TRUE;
                        } else {
                            // 如果可以被序列化的话, 从classMap中获取其owner class的引用
                            ClassReference clazz = classMap.get(new ClassReference.Handle(owner));
                            // 这部分逻辑在上一节已经出现过了, 找到声明该变量的class, 判断变量是否被transient修饰
                            while (clazz != null) {
                                for (ClassReference.Member member : clazz.getMembers()) {
                                    if (member.getName().equals(name)) {
                                        isTransient = (member.getModifiers() & Opcodes.ACC_TRANSIENT) != 0;
                                        break;
                                    }
                                }
                                if (isTransient != null) {
                                    break;
                                }
                                clazz = classMap.get(new ClassReference.Handle(clazz.getSuperClass()));
                            }
                        }
                        // newTaint模拟的是GETFIELD指令的结果
                        Set<String> newTaint = new HashSet<>();
                        // 如果变量不被transient修饰的话
                        if (!Boolean.TRUE.equals(isTransient)) {
                            // 获取栈顶的元素 (此时栈顶的元素是成员变量的owner class的对象引用, 在这里用字符串表示)
                            for (String s : getStackTaint(0)) {
                                // 将格式为<class_name>.<field_name>的一串字符加入到newTaint中
                                newTaint.add(s + "." + name);
                            }
                        }
                        // 委派给父类，模拟栈帧的变化
                        super.visitFieldInsn(opcode, owner, name, desc);
                        // 将newTaint放到栈顶, GETFIELD指令执行完毕
                        setStackTaint(0, newTaint);
                        return;
                    }
                    break;
                case Opcodes.PUTFIELD:
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            super.visitFieldInsn(opcode, owner, name, desc);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            // 获取方法参数的类型
            Type[] argTypes = Type.getArgumentTypes(desc);
            // 非静态方法的参数列表要加this
            if (opcode != Opcodes.INVOKESTATIC) {
                Type[] extendedArgTypes = new Type[argTypes.length+1];
                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                extendedArgTypes[0] = Type.getObjectType(owner);
                argTypes = extendedArgTypes;
            }

            switch (opcode) {
                case Opcodes.INVOKESTATIC:
                case Opcodes.INVOKEVIRTUAL:
                case Opcodes.INVOKESPECIAL:
                case Opcodes.INVOKEINTERFACE:
                    int stackIndex = 0;
                    for (int i = 0; i < argTypes.length; i++) {
                        int argIndex = argTypes.length-1-i;
                        Type type = argTypes[argIndex];
                        // 调用方法前所有参数已经入栈，根据索引获取操作数栈上的参数
                        Set<String> taint = getStackTaint(stackIndex);
                        if (taint.size() > 0) {
                            for (String argSrc : taint) {
                                if (!argSrc.substring(0, 3).equals("arg")) {
                                    throw new IllegalStateException("Invalid taint arg: " + argSrc);
                                }
                                // 从操作数栈上取出来的参数有两种情况
                                //   1. "arg0"这种形式，它表示方法中的参数
                                //   2. "arg0.<filed>"这种形式，表示获取了某个参数的某个成员变量
                                int dotIndex = argSrc.indexOf('.');
                                int srcArgIndex;
                                String srcArgPath;
                                if (dotIndex == -1) {   // dotIndex == -1对应第1种情况
                                    // 获取参数的索引位
                                    srcArgIndex = Integer.parseInt(argSrc.substring(3));
                                    srcArgPath = null;
                                } else {    // else-branch对应第2种情况
                                    // 获取参数的索引位
                                    srcArgIndex = Integer.parseInt(argSrc.substring(3, dotIndex));
                                    // 额外获取了一个srcArgPath，也就是"arg0.<field>"的"<field>"部分
                                    srcArgPath = argSrc.substring(dotIndex+1);
                                }

                                // 将这些信息用GraphCall包装起来
                                discoveredCalls.add(new GraphCall(
                                        new MethodReference.Handle(new ClassReference.Handle(this.owner), this.name, this.desc),
                                        new MethodReference.Handle(new ClassReference.Handle(owner), name, desc),
                                        srcArgIndex,    // srcArgIndex表示caller的参数索引
                                        srcArgPath,     // srcArgPath表示"<field>"部分呢
                                        argIndex));     // argIndex表示callee的参数索引
                            }
                        }

                        stackIndex += type.getSize();
                    }
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }
            // 模拟操作数栈变化
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }

    public static void main(String[] args) throws Exception {
        ClassLoader classLoader = Util.getWarClassLoader(Paths.get(args[0]));

        CallGraphDiscovery callGraphDiscovery = new CallGraphDiscovery();
        callGraphDiscovery.discover(new ClassResourceEnumerator(classLoader), new JavaDeserializationConfig());
        callGraphDiscovery.save();
    }
}
