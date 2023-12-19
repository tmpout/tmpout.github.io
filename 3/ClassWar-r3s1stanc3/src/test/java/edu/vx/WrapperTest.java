package edu.vx;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class WrapperTest {
  private static final byte[] CLASS_BYTES;

  private static final Class<?> CLASS = ClassToWrap.class;

  static {
    try {
      CLASS_BYTES = Files.readAllBytes(Paths.get("./target/test-classes/edu/vx/ClassToWrap.class"));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void testStatic()
      throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
          IllegalAccessException {
    int expected = ClassToWrap.add(1, 2);
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);
    Object actual = wrapper.getMethod("add", int.class, int.class).invoke(null, 1, 2);
    assertEquals(expected, actual);
  }

  @Test
  public void testMethod()
      throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
          InstantiationException, IllegalAccessException {
    int expected = new ClassToWrap<>(1).add(2);
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);
    Object instance = wrapper.getConstructor(Integer.class).newInstance(1);
    Object actual = wrapper.getMethod("add", int.class).invoke(instance, 2);
    assertEquals(expected, actual);
  }

  @Test
  public void testGeneric()
      throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
          InstantiationException, IllegalAccessException {
    int expected = new ClassToWrap<>(0).identity(42);
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);
    Object instance = wrapper.getConstructor(Integer.class).newInstance(0);
    Object actual = wrapper.getMethod("identity", Object.class).invoke(instance, 42);
    assertEquals(expected, actual);
  }

  @Test
  public void testException()
      throws IOException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException {
    assertThrows(CloneNotSupportedException.class, ClassToWrap::throwing);
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);
    try {
      wrapper.getMethod("throwing").invoke(null);
    } catch (InvocationTargetException e) {
      assertInstanceOf(CloneNotSupportedException.class, e.getTargetException());
    }
  }

  @Test
  public void testGenericException()
      throws IOException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException {
    assertThrows(CloneNotSupportedException.class, ClassToWrap::throwingGeneric);
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);
    try {
      wrapper.getMethod("throwingGeneric").invoke(null);
    } catch (InvocationTargetException e) {
      assertInstanceOf(CloneNotSupportedException.class, e.getTargetException());
    }
  }

  @Test
  public void testNoException() throws IOException, ClassNotFoundException {
    assertDoesNotThrow(() -> ClassToWrap.notThrowing());

    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);
    assertDoesNotThrow(() -> wrapper.getMethod("notThrowing").invoke(null));
  }

  @Test
  public void testInnerModification()
      throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
          InstantiationException, IllegalAccessException {
    ClassToWrap<Integer> expectedInstance = new ClassToWrap<>(1);
    expectedInstance.inc();
    int expected = expectedInstance.add(2);
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);
    Object instance = wrapper.getConstructor(Integer.class).newInstance(1);
    wrapper.getMethod("inc").invoke(instance);
    Object actual = wrapper.getMethod("add", int.class).invoke(instance, 2);
    assertEquals(expected, actual);
  }

  @Test
  public void testGlobal()
      throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
          InstantiationException, IllegalAccessException {
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);

    assertEquals(0, wrapper.getMethod("modifyGlobal", int.class).invoke(null, 1));

    Object instanceA = wrapper.getConstructor(Integer.class).newInstance(2);
    assertEquals(1, wrapper.getMethod("modifyGlobal").invoke(instanceA));

    Object instanceB = wrapper.getConstructor(Integer.class).newInstance(3);
    assertEquals(2, wrapper.getMethod("modifyGlobal").invoke(instanceB));
  }

  @Test
  public void testParametrizedReturn()
      throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
          IllegalAccessException {
    String value = "asdf";
    List<String> expected = ClassToWrap.list(value);
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);

    assertEquals(expected, wrapper.getMethod("list", Object.class).invoke(null, value));
  }

  @Test
  public void testParametrizedParameter()
      throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
          IllegalAccessException {
    List<String> value = Collections.singletonList("asdf");
    String expected = ClassToWrap.first(value);
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);

    assertEquals(expected, wrapper.getMethod("first", List.class).invoke(null, value));
  }

  @Test
  public void testMultipleParameters()
      throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
          IllegalAccessException {
    Map<? super Integer, ? extends Integer> expected = ClassToWrap.singletonMap(1, 2);
    Class<?> wrapper = wrap(CLASS, CLASS_BYTES);

    assertEquals(
        expected, wrapper.getMethod("singletonMap", Object.class, Object.class).invoke(null, 1, 2));
  }

  private static Class<?> wrap(Class<?> clazz, byte[] classBytes)
      throws IOException, ClassNotFoundException, ClassWar.NotImplemented {
    String source = ClassWar.infectionWrapper(clazz, classBytes);
    try (InMemoryFileManager fileManager =
        ClassWar.compile(
            Collections.singletonList(new InMemoryJavaFile(clazz.getName(), source)))) {
      String prefix = clazz.getName().replace('.', '/');
      InMemoryJavaFile[] files =
          fileManager.storage().entrySet().stream()
              .filter(e -> e.getKey().startsWith(prefix))
              .map(Map.Entry::getValue)
              .map(f -> (InMemoryJavaFile) f)
              .toArray(InMemoryJavaFile[]::new);

      return new JavaFileClassLoader(files).loadClass(clazz.getName());
    }
  }

  public static class JavaFileClassLoader extends ClassLoader {
    public JavaFileClassLoader(InMemoryJavaFile... files) {
      for (InMemoryJavaFile file : files) {
        byte[] classBytes = file.content();
        String name = file.getName();
        if (name.endsWith(".class")) {
          name = name.substring(0, name.length() - ".class".length());
        }
        name = name.replace('/', '.');
        name = name.substring(1);
        defineClass(name, classBytes, 0, classBytes.length);
      }
    }
  }
}
