# Just Another JAR Head

Many revelations ago, there was an angsty kid trying to understand the world and
computers. Said kid did write a virus that is able to infect Java ARchives (JAR)
by overwriting the entry point. The code was released in Valhalla #3 [0]. After
the release Peter Ferrie[1] published a crushing analysis of the virus[2]
finding more than a handful of bugs and naming it `HandJar`. That kid was me.
Now I'm sitting here, 10 years later, having studied the dark arts of computer
science, worked with Java professionally for 8 years and feeling jiggly to write
a virus again.

This article will not develop any new techniques but improve upon the findings
in[2], describe what the virus actually does, how it works and introduce
`HandJar.B`. The article is part of a series starting from revisiting,
understanding, fixing and improving the technique described in[0], going on to
explore new techniques for Java viruses.


## What happened?

Since the release of HandJar, hh86 released a pair of viruses that are able to
infect PE files from Java bytecode[11] and vice versa[12]. Class files are
infected by first inserting the virus code into the target Class and changing
the code of another method to invoke the virus code.

I also stumbled over `Java-Infector` by jlxip[13], that uses the same entry
point technique as HandJar but directly invokes the Java compiler binary
`javac`.


## What's in that JAR?

To understand the described infection technique, one needs to understand how
Java in general and specifically JARs are executed. When compiling Java code,
the compiler creates one Class file per object, each containing the compiled
bytecode. This bytecode is then executed on the Java Virtual Machine (JVM).
Since most code does not exist in a vacuum but depends on other classes, Java
has the concept of a Class Path which points to path(s) from which other Class
files can be loaded. This solves the problem of using other classes but would
result in many files and no clear entry point for users of the application. Java
applications can also exist as JARs, which are ZIP archives containing all of
the application's classes. Inside these JARs, there can be a metadata file
inside `META-INF/MANIFEST.MF`[3]. This file contains one key-value pair per
line, separated by a colon and space `: ` and can contain information like
compiler version/vendor or build time. The `Main-Class` property is used by the
JVM to decide which class in a JAR is the entry point. The `Main-Class`'s `main`
method is called passing command line arguments as a parameter. `MANIFEST.MF`
must end with a trailing newline, otherwise the last property is ignored.


## Spitting in the JAR

The JAR infection technique explored in this article works like the following:
Create a new entry point that executes the virus, returns control to the old
entry point and overwrite `Main-Class` in `MANIFEST.MF` to point to the new
entry point. This can either be achieved by manipulating, generating and
generally fiddling with JVM bytecode or by using the `JavaCompiler` interface,
which can compile Java code at runtime, if a compiler is available (e.g. the
virus is executed using a full Java Development Kit (JDK) instead of a Java
Runtime Environment (JRE)).


## Problems in HandJar.A and Solutions for HandJar.B

`HandJar.A` was released in December 2012 and had more bugs than features. This
article aims to create `HandJar.B`, the next iteration having fewer bugs and
<<<<<<< HEAD
maybe more features. Let's discuss what was wrong, needs to be fixed, and how I
=======
maybe more features. Let's discuss what was wrong, needs to be fixed and how I
>>>>>>> 52c9398 (Update with header)
plan on fixing it:

* Confusion on how to use path separators: The initial version of HandJar tried
  to use path separators depending on the running OS, not knowing that Windows
  understands forward slashes. The improved version should simply use
  `java.nio.Path` instead of stringly typed paths.

* Confusion about line separators: When parsing the `MANIFEST.MF`, the initial
  version used the OS specific line separator, causing problems for JARs that
  were generated on an OS that uses different separators. The improved version
  should be able to split on any valid line separator. We will be using a regex
  pattern matching the allowed newline chars to parse the `MANIFEST.MF`.

* Errors parsing and manipulating `MANIFEST.MF`: The parsing errors came from
  depending on the OS line separator. Replacing the entry point was done using
  simple `String#replace` which would break if the initial entry point was
  called `Main`. `manifest.replace("Main", newEntry)` would also replace `Main`
  in `Main-Class`. The improved version should properly parse and manipulate
  `MANIFEST.MF`.

* Don't make a sandwich: When infecting a new file, HandJar would copy all files
  from the virus to the new host. This is no problem for generation 0, but later
  generations would copy all classes from the currently running generation to
  the new host, resulting in ever growing JARs. We need to keep track of the
  virus' classes and make sure to only copy those classes.

There are other improvements I want to implement:

* Perform infection completely in-memory. Overwriting the host file should be
  the only time when disk IO is performed. Reading files, creating ZIP archives
  and copying from one archive to a new one can be done in-memory using the
  `InputStream` and `OutputStream` interfaces and their `ByteArrayInputStream`
  and `ByteArrayOutputStream` implementations. Keeping Java source code and
  freshly compiled Class files in-memory will be explored in the next section.

* Don't destroy the host by better checking, which JARs should be infected:

  - Check that no Class with the same name as any of the virus' classes exists,
    so we don't overwrite any classes of the host
  - Don't infect signed JARs. Changing a signed JAR would invalidate the
    signature and break the host


## What's a JavaCompiler?

The Java standard library contains a `JavaCompiler` interface[4] to compile Java
source code at runtime. An actual implementation of the interface is only
available when running on a JDK and can be constructed using
`ToolProvider#getSystemJavaCompiler`[5]. The `JavaCompiler#getTask`[6] method
takes the compilation units (Java source code) and some additional parameters
for compiler flags, logging, file management and diagnostics and creates a
`CompilationTask` which can then be executed. Everything except the compilation
units has default values which were used in HandJar.A.

Compilation units must implement the `JavaFileObject`[7] interface, which
abstracts file access away using the `FileObject`[8] interface. HandJar.A
implemented/copied a `JavaSourceFromString` class that could hold any Java code
in a Java String object. This was the basis for compiling code in-memory but
wrote the compiled Class files to the current directory.

The `JavaFileManager`[9] interface describes how files in a compilation process
are accessed. The default implementation uses the current directory and behaves
just as `javac` does when invoked from the command line. Using a custom
`InMemoryFileManager` implementation of the interface, it is possible to store
files inside a `Map<String, JavaFileObject>` mapping paths to Java files without
writing to the disk. The `JavaSourceFromString` object only allowed storing
strings but it is a minor change to hold byte arrays instead. This allows for a
new `InMemoryJavaFile` class that can hold either Java source code or compiled
Class files in-memory.

The entry point that gets compiled when infecting a new host uses some classes
from the Java standard library (e.g. `Thread` to execute the infection routine
an payload without blocking the host execution). There is an
`ForwardingJavaFileManager`[15] interface, that allows overwriting some methods
from `JavaFileManager` and forwards the rest to a delegate. That way, when the
compiler requests a file, we first try to look it up in our `Map<String,
JavaFileObject>` and fall back to the standard file manager if it was not found.
When creating a new file, we just insert a new entry in the map. This could be
extended by including any bundled libraries so we could even use those in our
entry point but for now, HandJar only uses the Java standard library.

This combination of `InMemoryJavaFile` and `InMemoryFileManager` allows
HandJar.B to hold Java code in-memory, compile it to Java bytecode at runtime
and store the resulting Class file also in-memory. These Class files can then be
written to the newly created JAR that contains the modified `MANIFEST.MF`, the
new entry point, the virus' classes and everything from the host JAR.


## What's Behind that JAR?

Having a fixed and working implementation of the ideas from HandJar.A, what's
next? One big limitation of HandJar is, that it can only infect JARs with a
`Main-Class`. This excludes Java libraries, Web application ARchives (WAR) and
Enterprise Application aRchives (EAR). I will look into Java libraries next and
develop new entry point techniques that do not depend on the `Main-Class`
attribute.

Java Class files have different versions and older versions of the JVM cannot
execute Class files produced by newer versions of the JVM. Before infecting a
JAR file, it should be checked, that all Class files in the host are at least
the same Class file version as the compiled entry point and other virus classes.
Otherwise a host might be destroyed if it is executed by an incompatible JVM.
When exploring new entry point techniques, I will also look into this. While at
it, it might be interesting to look into framework specific entry points. I'm
thinking about annotation based frameworks like Spring Boot[14], where it should
be possible to get our virus code to execute by compiling a class with the right
annotations.


[0]: https://86hh.github.io/valhalla/issue%203/vessel/display/articles/R3s1stanc3/javainfector_article.txt
[1]: http://pferrie.epizy.com/
[2]: https://www.virusbulletin.com/virusbulletin/2013/12/hands-cookie-jar
[3]: https://docs.oracle.com/en/java/javase/17/docs/specs/jar/jar.html#jar-manifest
[4]: https://docs.oracle.com/javase/8/docs/api/javax/tools/JavaCompiler.html
[5]: https://docs.oracle.com/javase/8/docs/api/javax/tools/ToolProvider.html#getSystemJavaCompiler--
[6]: https://docs.oracle.com/javase/8/docs/api/javax/tools/JavaCompiler.html#getTask-java.io.Writer-javax.tools.JavaFileManager-javax.tools.DiagnosticListener-java.lang.Iterable-java.lang.Iterable-java.lang.Iterable-
[7]: https://docs.oracle.com/javase/8/docs/api/javax/tools/JavaFileObject.html
[8]: https://docs.oracle.com/javase/8/docs/api/javax/tools/FileObject.html
[9]: https://docs.oracle.com/javase/8/docs/api/javax/tools/JavaFileManager.html
[10]: https://docs.oracle.com/javase/8/docs/api/javax/tools/JavaCompiler.html#getStandardFileManager-javax.tools.DiagnosticListener-java.util.Locale-java.nio.charset.Charset-
[11]: https://86hh.github.io/valhalla/issue%204/articles/hh86/JBSO.TXT
[12]: https://86hh.github.io/valhalla/issue%204/articles/hh86/CLASSI.TXT
[13]: https://github.com/jlxip/Java-Infector
[14]: https://spring.io/projects/spring-boot
[15]: https://docs.oracle.com/javase/8/docs/api/javax/tools/ForwardingJavaFileManager.html


r3s1stanc3 - r3s1stanc3@riseup.net

2023-08
