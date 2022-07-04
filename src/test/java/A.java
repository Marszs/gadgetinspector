public class A {
    private final String name = "A";

    void methA() {
        String name = this.name;
        B b = new B();
        System.out.println(b.name);
        String name_b = b.methB(name);
    }
}
