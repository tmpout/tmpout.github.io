package edu.vx;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.*;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaFileManager;
import javax.tools.JavaFileObject;

public class InMemoryFileManager extends ForwardingJavaFileManager<JavaFileManager> {
  private final Map<String, JavaFileObject> storage = new HashMap<>();

  public static String key(String... parts) {
    return key(JavaFileObject.Kind.OTHER, parts);
  }

  public static String key(JavaFileObject.Kind kind, String... parts) {
    StringBuilder result = new StringBuilder();
    for (String part : parts) {
      result.append(Paths.get(part).normalize().toString().replace('.', '/'));
    }
    return result.append(kind.extension).toString();
  }

  public InMemoryFileManager(JavaFileManager delegate) {
    super(delegate);
  }

  @Override
  public Iterable<JavaFileObject> list(
      Location location, String packageName, Set<JavaFileObject.Kind> kinds, boolean recurse)
      throws IOException {
    List<JavaFileObject> result = new ArrayList<>();
    for (Map.Entry<String, JavaFileObject> entry : storage.entrySet()) {
      if (entry.getKey().startsWith(key(packageName))
          && kinds.contains(entry.getValue().getKind())) {
        // TODO: check recurse
        result.add(entry.getValue());
      }
    }
    for (JavaFileObject jfo : super.list(location, packageName, kinds, recurse)) {
      result.add(jfo);
    }
    return result;
  }

  @Override
  public boolean isSameFile(FileObject a, FileObject b) {
    return a.getName().equals(b.getName()) || super.isSameFile(a, b);
  }

  @Override
  public boolean hasLocation(Location location) {
    for (String path : storage.keySet()) {
      if (path.startsWith(location.getName())) {
        return true;
      }
    }
    return super.hasLocation(location);
  }

  @Override
  public JavaFileObject getJavaFileForInput(
      Location location, String className, JavaFileObject.Kind kind) throws IOException {
    JavaFileObject file = storage.get(key(kind, className));
    return file == null ? super.getJavaFileForInput(location, className, kind) : file;
  }

  @Override
  public JavaFileObject getJavaFileForOutput(
      Location location, String className, JavaFileObject.Kind kind, FileObject sibling)
      throws IOException {
    JavaFileObject file = getJavaFileForInput(location, className, kind);
    if (file == null) {
      JavaFileObject result = new InMemoryJavaFile(key(className), kind);
      storage.put(key(kind, className), result);
      return result;
    } else {
      return file;
    }
  }

  @Override
  public FileObject getFileForInput(Location location, String packageName, String relativeName)
      throws IOException {
    String key = key(packageName, relativeName);
    JavaFileObject file = storage.get(key);
    return file == null ? super.getFileForInput(location, packageName, relativeName) : file;
  }

  @Override
  public FileObject getFileForOutput(
      Location location, String packageName, String relativeName, FileObject sibling)
      throws IOException {
    FileObject file = getFileForInput(location, packageName, relativeName);
    if (file == null) {
      JavaFileObject result =
          new InMemoryJavaFile(key(packageName, relativeName), fromName(relativeName));
      storage.put(key(packageName, relativeName), result);
      return result;
    } else {
      return file;
    }
  }

  private static JavaFileObject.Kind fromName(final String name) {
    for (JavaFileObject.Kind kind : JavaFileObject.Kind.values()) {
      if (name.endsWith(kind.extension)) {
        return kind;
      }
    }
    return JavaFileObject.Kind.OTHER;
  }

  public Map<String, JavaFileObject> storage() {
    return Collections.unmodifiableMap(storage);
  }

  public void execute(String className, String methodName, Object... params)
      throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException,
          IllegalAccessException {
    Class<?>[] paramClasses = new Class<?>[params.length];
    for (int i = 0; i < params.length; i++) {
      paramClasses[i] = params[i].getClass();
    }

    ClassLoader cl = getClassLoader(null);
    Class<?> mainClass = cl.loadClass(className);
    Method entry = mainClass.getMethod(methodName, paramClasses);
    entry.invoke(null, params);
  }
}
