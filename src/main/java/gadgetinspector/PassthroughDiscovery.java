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
import java.util.*;

public class PassthroughDiscovery {

    private static final Logger LOGGER = LoggerFactory.getLogger(PassthroughDiscovery.class);

    private final Map<MethodReference.Handle, Set<MethodReference.Handle>> methodCalls = new HashMap<>();
    private Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;

    public void discover(final ClassResourceEnumerator classResourceEnumerator, final GIConfig config) throws IOException {
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        Map<ClassReference.Handle, ClassReference> classMap = DataLoader.loadClasses();
        InheritanceMap inheritanceMap = InheritanceMap.load();

        Map<String, ClassResourceEnumerator.ClassResource> classResourceByName = discoverMethodCalls(classResourceEnumerator);
        List<MethodReference.Handle> sortedMethods = topologicallySortMethodCalls();
        passthroughDataflow = calculatePassthroughDataflow(classResourceByName, classMap, inheritanceMap, sortedMethods,
                config.getSerializableDecider(methodMap, inheritanceMap));
    }

    private Map<String, ClassResourceEnumerator.ClassResource> discoverMethodCalls(final ClassResourceEnumerator classResourceEnumerator) throws IOException {
        Map<String, ClassResourceEnumerator.ClassResource> classResourcesByName = new HashMap<>();
        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(in);
                try {
                    MethodCallDiscoveryClassVisitor visitor = new MethodCallDiscoveryClassVisitor(Opcodes.ASM6);
                    cr.accept(visitor, ClassReader.EXPAND_FRAMES);
                    classResourcesByName.put(visitor.getName(), classResource);
                } catch (Exception e) {
                    LOGGER.error("Error analyzing: " + classResource.getName(), e);
                }
            }
        }
        return classResourcesByName;
    }

    private List<MethodReference.Handle> topologicallySortMethodCalls() {
        Map<MethodReference.Handle, Set<MethodReference.Handle>> outgoingReferences = new HashMap<>();
        for (Map.Entry<MethodReference.Handle, Set<MethodReference.Handle>> entry : methodCalls.entrySet()) {
            MethodReference.Handle method = entry.getKey();
            outgoingReferences.put(method, new HashSet<>(entry.getValue()));
        }

        // Topological sort methods
        LOGGER.debug("Performing topological sort...");
        Set<MethodReference.Handle> dfsStack = new HashSet<>();
        Set<MethodReference.Handle> visitedNodes = new HashSet<>();
        List<MethodReference.Handle> sortedMethods = new ArrayList<>(outgoingReferences.size());
        for (MethodReference.Handle root : outgoingReferences.keySet()) {
            dfsTsort(outgoingReferences, sortedMethods, visitedNodes, dfsStack, root);
        }
        LOGGER.debug(String.format("Outgoing references %d, sortedMethods %d", outgoingReferences.size(), sortedMethods.size()));

        return sortedMethods;
    }

    private static Map<MethodReference.Handle, Set<Integer>> calculatePassthroughDataflow(Map<String, ClassResourceEnumerator.ClassResource> classResourceByName,
                                                                                          Map<ClassReference.Handle, ClassReference> classMap,
                                                                                          InheritanceMap inheritanceMap,
                                                                                          List<MethodReference.Handle> sortedMethods,
                                                                                          SerializableDecider serializableDecider) throws IOException {
        final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = new HashMap<>();
        for (MethodReference.Handle method : sortedMethods) {
            if (method.getName().equals("<clinit>")) {
                continue;
            }
            ClassResourceEnumerator.ClassResource classResource = classResourceByName.get(method.getClassReference().getName());
            try (InputStream inputStream = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(inputStream);
                try {
                    PassthroughDataflowClassVisitor cv = new PassthroughDataflowClassVisitor(classMap, inheritanceMap,
                            passthroughDataflow, serializableDecider, Opcodes.ASM6, method);
                    cr.accept(cv, ClassReader.EXPAND_FRAMES);
                    // 访问完XRETURN指令之后方法也就执行完毕，调用getReturnTaint()方法获取污点分析的结果，以对应的方法为键，缓存到passthroughDataflow里面
                    passthroughDataflow.put(method, cv.getReturnTaint());
                } catch (Exception e) {
                    LOGGER.error("Exception analyzing " + method.getClassReference().getName(), e);
                }
            } catch (IOException e) {
                LOGGER.error("Unable to analyze " + method.getClassReference().getName(), e);
            }
        }
        return passthroughDataflow;
    }

    private class MethodCallDiscoveryClassVisitor extends ClassVisitor {
        public MethodCallDiscoveryClassVisitor(int api) {
            super(api);
        }

        private String name = null;

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            if (this.name != null) {
                throw new IllegalStateException("ClassVisitor already visited a class!");
            }
            this.name = name;
        }

        public String getName() {
            return name;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
            MethodCallDiscoveryMethodVisitor modelGeneratorMethodVisitor = new MethodCallDiscoveryMethodVisitor(
                    api, mv, this.name, name, desc);

            return new JSRInlinerAdapter(modelGeneratorMethodVisitor, access, name, desc, signature, exceptions);
        }

        @Override
        public void visitEnd() {
            super.visitEnd();
        }
    }

    private class MethodCallDiscoveryMethodVisitor extends MethodVisitor {
        private final Set<MethodReference.Handle> calledMethods;

        public MethodCallDiscoveryMethodVisitor(final int api, final MethodVisitor mv,
                                           final String owner, String name, String desc) {
            super(api, mv);

            this.calledMethods = new HashSet<>();
            methodCalls.put(new MethodReference.Handle(new ClassReference.Handle(owner), name, desc), calledMethods);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            calledMethods.add(new MethodReference.Handle(new ClassReference.Handle(owner), name, desc));
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }

    public void save() throws IOException {
        if (passthroughDataflow == null) {
            throw new IllegalStateException("Save called before discover()");
        }

        DataLoader.saveData(Paths.get("passthrough.dat"), new PassThroughFactory(), passthroughDataflow.entrySet());
    }

    public static Map<MethodReference.Handle, Set<Integer>> load() throws IOException {
        Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = new HashMap<>();
        for (Map.Entry<MethodReference.Handle, Set<Integer>> entry : DataLoader.loadData(Paths.get("passthrough.dat"), new PassThroughFactory())) {
            passthroughDataflow.put(entry.getKey(), entry.getValue());
        }
        return passthroughDataflow;
    }

    public static class PassThroughFactory implements DataFactory<Map.Entry<MethodReference.Handle, Set<Integer>>> {

        @Override
        public Map.Entry<MethodReference.Handle, Set<Integer>> parse(String[] fields) {
            ClassReference.Handle clazz = new ClassReference.Handle(fields[0]);
            MethodReference.Handle method = new MethodReference.Handle(clazz, fields[1], fields[2]);

            Set<Integer> passthroughArgs = new HashSet<>();
            for (String arg : fields[3].split(",")) {
                if (arg.length() > 0) {
                    passthroughArgs.add(Integer.parseInt(arg));
                }
            }
            return new AbstractMap.SimpleEntry<>(method, passthroughArgs);
        }

        @Override
        public String[] serialize(Map.Entry<MethodReference.Handle, Set<Integer>> entry) {
            if (entry.getValue().size() == 0) {
                return null;
            }

            final String[] fields = new String[4];
            fields[0] = entry.getKey().getClassReference().getName();
            fields[1] = entry.getKey().getName();
            fields[2] = entry.getKey().getDesc();

            StringBuilder sb = new StringBuilder();
            for (Integer arg : entry.getValue()) {
                sb.append(Integer.toString(arg));
                sb.append(",");
            }
            fields[3] = sb.toString();

            return fields;
        }
    }

    private static void dfsTsort(Map<MethodReference.Handle, Set<MethodReference.Handle>> outgoingReferences,
                                    List<MethodReference.Handle> sortedMethods, Set<MethodReference.Handle> visitedNodes,
                                    Set<MethodReference.Handle> stack, MethodReference.Handle node) {

        if (stack.contains(node)) {
            return;
        }
        if (visitedNodes.contains(node)) {
            return;
        }
        Set<MethodReference.Handle> outgoingRefs = outgoingReferences.get(node);
        if (outgoingRefs == null) {
            return;
        }

        stack.add(node);
        for (MethodReference.Handle child : outgoingRefs) {
            dfsTsort(outgoingReferences, sortedMethods, visitedNodes, stack, child);
        }
        stack.remove(node);
        visitedNodes.add(node);
        sortedMethods.add(node);
    }

    private static class PassthroughDataflowClassVisitor extends ClassVisitor {

        Map<ClassReference.Handle, ClassReference> classMap;
        private final MethodReference.Handle methodToVisit;
        private final InheritanceMap inheritanceMap;
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        private final SerializableDecider serializableDecider;

        private String name;
        private PassthroughDataflowMethodVisitor passthroughDataflowMethodVisitor;

        public PassthroughDataflowClassVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                InheritanceMap inheritanceMap, Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                SerializableDecider serializableDecider, int api, MethodReference.Handle methodToVisit) {
            super(api);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.methodToVisit = methodToVisit;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDecider;
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.name = name;
            if (!this.name.equals(methodToVisit.getClassReference().getName())) {
                throw new IllegalStateException("Expecting to visit " + methodToVisit.getClassReference().getName() + " but instead got " + this.name);
            }
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {
            if (!name.equals(methodToVisit.getName()) || !desc.equals(methodToVisit.getDesc())) {
                return null;
            }
            if (passthroughDataflowMethodVisitor != null) {
                throw new IllegalStateException("Constructing passthroughDataflowMethodVisitor twice!");
            }

            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
            passthroughDataflowMethodVisitor = new PassthroughDataflowMethodVisitor(
                    classMap, inheritanceMap, this.passthroughDataflow, serializableDecider,
                    api, mv, this.name, access, name, desc, signature, exceptions);

            return new JSRInlinerAdapter(passthroughDataflowMethodVisitor, access, name, desc, signature, exceptions);
        }

        public Set<Integer> getReturnTaint() {
            if (passthroughDataflowMethodVisitor == null) {
                throw new IllegalStateException("Never constructed the passthroughDataflowmethodVisitor!");
            }
            return passthroughDataflowMethodVisitor.returnTaint;
        }
    }

    private static class PassthroughDataflowMethodVisitor extends TaintTrackingMethodVisitor<Integer> {

        private final Map<ClassReference.Handle, ClassReference> classMap;
        private final InheritanceMap inheritanceMap;
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        private final SerializableDecider serializableDecider;

        private final int access;
        private final String desc;
        private final Set<Integer> returnTaint;

        public PassthroughDataflowMethodVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                InheritanceMap inheritanceMap, Map<MethodReference.Handle,
                Set<Integer>> passthroughDataflow, SerializableDecider serializableDeciderMap, int api, MethodVisitor mv,
                String owner, int access, String name, String desc, String signature, String[] exceptions) {
            super(inheritanceMap, passthroughDataflow, api, mv, owner, access, name, desc, signature, exceptions);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDeciderMap;
            this.access = access;
            this.desc = desc;
            returnTaint = new HashSet<>();
        }

        @Override
        public void visitCode() {
            super.visitCode();

            int localIndex = 0;
            int argIndex = 0;
            if ((this.access & Opcodes.ACC_STATIC) == 0) {
                setLocalTaint(localIndex, argIndex);
                localIndex += 1;
                argIndex += 1;
            }
            for (Type argType : Type.getArgumentTypes(desc)) {
                setLocalTaint(localIndex, argIndex);
                localIndex += argType.getSize();
                argIndex += 1;
            }
        }

        @Override
        public void visitInsn(int opcode) {
            // 当访问到一些XRETURN指令的时候，也即方法调用完的时候，这时候栈顶的元素就是方法的执行结果，在GI的“模拟”中为入参污点分析的结果
            switch(opcode) {
                case Opcodes.IRETURN:
                case Opcodes.FRETURN:
                case Opcodes.ARETURN:
                    // int, float, 引用类型占1个size，所以直接返回栈顶的污点分析结果即可
                    returnTaint.addAll(getStackTaint(0));
                    break;
                case Opcodes.LRETURN:
                case Opcodes.DRETURN:
                    // long, double占2个size，所以要返回栈顶元素的下一个元素（栈顶元素为空的占位符）
                    returnTaint.addAll(getStackTaint(1));
                    break;
                case Opcodes.RETURN:
                    // RETURN指令返回void，不做处理
                    break;
                default:
                    // 其他指令，不处理
                    break;
            }

            super.visitInsn(opcode);
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String desc) {

            switch (opcode) {
                case Opcodes.GETSTATIC:
                    break;
                case Opcodes.PUTSTATIC:
                    break;
                case Opcodes.GETFIELD:
                    Type type = Type.getType(desc);
                    if (type.getSize() == 1) {
                        Boolean isTransient = null;

                        // If a field type could not possibly be serialized, it's effectively transient
                        if (!couldBeSerialized(serializableDecider, inheritanceMap, new ClassReference.Handle(type.getInternalName()))) {
                            isTransient = Boolean.TRUE;
                        } else {
                            ClassReference clazz = classMap.get(new ClassReference.Handle(owner));
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

                        Set<Integer> taint;
                        if (!Boolean.TRUE.equals(isTransient)) {
                            taint = getStackTaint(0);
                        } else {
                            taint = new HashSet<>();
                        }

                        super.visitFieldInsn(opcode, owner, name, desc);
                        setStackTaint(0, taint);
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
            // 获取方法的参数类型
            Type[] argTypes = Type.getArgumentTypes(desc);
            // 如果不是静态方法调用的话，参数0是this，其他参数往后顺延
            if (opcode != Opcodes.INVOKESTATIC) {
                Type[] extendedArgTypes = new Type[argTypes.length + 1];
                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                extendedArgTypes[0] = Type.getObjectType(owner);
                argTypes = extendedArgTypes;
            }
            // 获取返回值类型所占的size大小
            int retSize = Type.getReturnType(desc).getSize();
            // 调用的方法的返回值受参数污染的索引集合
            Set<Integer> resultTaint;
            switch (opcode) {
                // 四种方法调用：静态方法，普通方法，特殊方法，接口方法
                case Opcodes.INVOKESTATIC:
                case Opcodes.INVOKEVIRTUAL:
                case Opcodes.INVOKESPECIAL:
                case Opcodes.INVOKEINTERFACE:
                    // 传入参数的污点集合
                    final List<Set<Integer>> argTaint = new ArrayList<Set<Integer>>(argTypes.length);
                    for (int i = 0; i < argTypes.length; i++) {
                        // null占位
                        argTaint.add(null);
                    }

                    int stackIndex = 0;
                    // 方法调用的时候参数从右往左存储在栈中
                    for (int i = 0; i < argTypes.length; i++) {
                        Type argType = argTypes[i];
                        if (argType.getSize() > 0) {
                            // 在执行方法调用的指令之前，参数就已经在操作数栈上了，所以这里直接获取即可
                            // 根据参数顺序，依次从操作数栈中获取参数
                            // 注意这里并不会从栈中pop出参数，这里仅仅是“静态”分析，模拟栈帧变化是父类该方法要做的事
                            argTaint.set(argTypes.length - 1 - i, getStackTaint(stackIndex + argType.getSize() - 1));
                        }
                        // index根据参数类型的size递增
                        stackIndex += argType.getSize();
                    }

                    // 如果调用的是构造方法
                    if (name.equals("<init>")) {
                        // Pass result taint through to original taint set; the initialized object is directly tainted by
                        // parameters
                        // 构造方法会返回类的实例对象，也就是this，那么方法返回结果的污点集合必然会受到this的污染
                        // 所以将this添加到结果的污点集合中
                        resultTaint = argTaint.get(0);
                    } else {
                        // 如果是其他方法调用，那么返回值的污点集合先初始化为空的Set
                        resultTaint = new HashSet<>();
                    }
                    // passthroughDataflow也就是calculatePassthroughDataflow()方法返回的结果
                    // 这一步获取调用的方法的污点分析结果，即callee的返回值受哪个（些）参数的污染
                    // 由于已经进行了逆拓扑排序，所以调用的方法必然已经先被分析过，污染结果存在对应的passthrough中了
                    Set<Integer> passthrough = passthroughDataflow.get(new MethodReference.Handle(new ClassReference.Handle(owner), name, desc));
                    if (passthrough != null) {
                        for (Integer passthroughDataflowArg : passthrough) {
                            // 取出对应索引上的参数，然后添加到resultTaint中
                            resultTaint.addAll(argTaint.get(passthroughDataflowArg));
                        }
                    }
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            // 委派给父类，模拟JVM的栈帧变化
            super.visitMethodInsn(opcode, owner, name, desc, itf);

            if (retSize > 0) {
                // 如果方法有返回值，那么就把之前分析得到的resultTaint加入到栈顶的集合中
                // 此时栈顶的元素是父类的visitMethodInsn分析得到的污染结果
                getStackTaint(retSize - 1).addAll(resultTaint);
            }
        }
    }


    public static void main(String[] args) throws Exception {
        ClassLoader classLoader = Util.getWarClassLoader(Paths.get(args[0]));

        PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
        passthroughDiscovery.discover(new ClassResourceEnumerator(classLoader), new JavaDeserializationConfig());
        passthroughDiscovery.save();
    }
}
