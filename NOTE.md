




# 第三阶段 CallGraph方法调用关联

这一阶段获取的是caller和callee的参数关联，比如
```java
public class A {
    public void caller(String paramA) {
        new B().callee(paramA);
    }
}

class B {
    public String callee(String paramB) {
        return paramB;
    }
}
```
也就是分析的 `A.caller()` 方法的参数 `paramA` 和 `B.callee()` 方法的参数 `paramB` 之间的关系。

分析的起点依然是 `discover()` 方法
```java
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
```
`ModelGeneratorClassVisitor` 的核心依然是 `VisitMethod` 方法
```java
@Override
public MethodVisitor visitMethod(int access, String name, String desc,
                                 String signature, String[] exceptions) {
    MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
    // 核心MethodVisitor是ModelGeneratorMethodVisitor
    ModelGeneratorMethodVisitor modelGeneratorMethodVisitor = new ModelGeneratorMethodVisitor(classMap,
            inheritanceMap, passthroughDataflow, serializableDecider, api, mv, this.name, access, name, desc, signature, exceptions);

    return new JSRInlinerAdapter(modelGeneratorMethodVisitor, access, name, desc, signature, exceptions);
}
```
这里使用的 MethodVisitor 是 `ModelGeneratorClassVisitor`, `TaintTrackingMethodVisitor` 的子类之一。

下面是 `ModelGeneratorClassVisitor` 对方法的观察的核心方法，这个 MethodVisitor 只实现了三个方法，分别是 `visitCode()`, `visitFiledInsn()`, `visitMethodInsn()` 。

首先调用的是 `visitCode()` 方法
```java
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
```

其次是 `visitFieldInsn()` 方法
```java
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
```

