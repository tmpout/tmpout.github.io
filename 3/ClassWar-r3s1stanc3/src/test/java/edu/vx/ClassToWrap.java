package edu.vx;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@TestAnnotation("classLevel")
public class ClassToWrap<
    @TestAnnotation("genericClassLevel")
    T extends @TestAnnotation("genericBoundClassLevel") Integer> {
  private static int GLOBAL = 0;

  public static @TestAnnotation("staticReturn") int modifyGlobal(
      @TestAnnotation("staticParam") int value) {
    int old = GLOBAL;
    GLOBAL = value;
    return old;
  }

  public @TestAnnotation("memberMethodReturn") int modifyGlobal() {
    int old = GLOBAL;
    GLOBAL = i;
    return old;
  }

  public static int add(int a, int b) {
    return a + b;
  }

  private int i;

  @TestAnnotation("ctor")
  public ClassToWrap(@TestAnnotation("ctorParam") T i) {
    this.i = i;
  }

  public int add(@TestAnnotation("memberMethodParam") int a) {
    return i + a;
  }

  public void inc() {
    i += 1;
  }

  public <@TestAnnotation("methodGeneric") I> I identity(I value) {
    return value;
  }

  public static void throwing() throws @TestAnnotation("exception") CloneNotSupportedException {
    throw new CloneNotSupportedException();
  }

  public static void notThrowing() throws CloneNotSupportedException {}

  public static <E extends CloneNotSupportedException> void throwingGeneric() throws E {
    throw (E) new CloneNotSupportedException();
  }

  public static <I> List<I> list(I value) {
    return Collections.singletonList(value);
  }

  public static <I> I first(List<I> l) {
    return l.get(0);
  }

  public static <K, V> Map<? super K, ? extends V> singletonMap(K key, V value) {
    return Collections.singletonMap(key, value);
  }

  public class b<
          @edu.vx.TestAnnotation(
              value = "genericClassLevel",
              cls = java.lang.Object.class,
              foo = 3.0,
              bar = TestEnum.B,
              ann = @TestAnnotationInner())
          T extends
              java.lang.@TestAnnotation(
                      value = "genericBoundClassLevel",
                      cls = java.lang.Object.class,
                      foo = 3.0,
                      bar = TestEnum.B,
                      ann = @TestAnnotationInner())
                  Integer>
      extends java.lang.Object {}
}
