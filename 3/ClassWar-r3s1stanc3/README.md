# ClassWar

## Build Instructions and Requirements

* JDK 8 or higher
* Maven

```
# build the virus
mvn install

# run the demo (this will also (re)build the virus)
make demo
```

# Class War Against the Libs

In my last article I discussed infecting Java ARchives (JAR) by compiling a new
entry point and overwriting the `Main-Class` attribute in `MANIFEST.MF` to point
to the new entry point. This meant, the virus can only infect Java applications
using that attribute.

Java Classes can contain `static` blocks that are evaluated exactly once when
the Class is loaded (e.g. a new instance is created or a static method or member
is accessed). If we were able to insert a `static` block into any Class, we get
a new entry point, that is executed when this Class is loaded without requiring
a `Main-Class` attribute.

Simply placing a new Class into the JAR would not help, since none of the host's
Classes reference this new Class and it is therefore not loaded. We have to
somehow infect an existing Class, insert a `static` block calling the entry
point without changing the public API of the Class, so it can still be used as
before. Now if existing host code uses the infected class, the virus will be
executed. We could archive this by manipulating the Class file. While she chose
a different technique for EPO, this has already been done by hh86 in
`W32.Grimes`[0]. Manipulating Class files will be explored in a later chapter of
this series, for now we'll stick to what we already know and build a wrapper
around the Class-to-be-infected, compile the wrapper and overwrite the existing
class while hopefully not changing it's observable behaviour.


## Admiring My Own Reflection

Java Reflection[1, 2] allows inspecting Java Classes at runtime. We can access
members, invoke methods and create instances of Classes. Using a
`ClassLoader`[3], Classes can be loaded from various sources into the running
JVM instance. Using `ClassLoader#defineClass()`[4], any valid Class can be
loaded into the current JVM and invoked using reflection.

Let's start with a Class `Example`:

```
public class Example {
  public static int add(int a, int b) {
    return a + b;
  }
  private final int x;
  public Example(int x) {
    this.x = x;
  }
  public int addSelf(int y) {
    return this.x + y;
  }
}
```

The `Example` Class has a public function `add` (that can be used without
creating an instance of `Example`), a public constructor that takes an integer
and a public instance method `addSelf`. Using a `ClassLoader` and reflection,
the functions, constructors and methods can be invoked like this (the following
examples omit error handling):

```
Class<?> c = Example.class;
Method m = c.getMethod("add", int.class, int.class);
// `add` is a static method, so we can pass `null` as the instance
Object ret = m.invoke(null, 1, 2);
assert 3 == (int) ret;

Constructor<?> ctor = c.getDeclaredConstructor(int.class);
Object instance = ctor.newInstance(1);

Method m = c.getMethod("addSelf", int.class);
// `addSelf` is a member method, so we must pass a valid class instance to
// invoke the method
Object ret = m.invoke(instance, 2);
assert 3 == (int) ret;
```


## Reflecting About the Working Class

Knowing these basics about reflection, we can create a Class wrapper that
exposes exactly the same public API and behaviour as another Class. This wrapper
Class can also contain a `static` block, the entry point of the virus, which
will be invoked once the Class is referenced in any way. Each method passes its
parameters to the according method of the wrapped Class. Instance methods are
delegated to an instance of the wrapped Class that is created in the
constructor. The wrapper looks like this:

```
public class Example {
  private static final Class<?> CLASS = todo();
  private final Object delegate;

  public static int add(int a, int b) {
    Method m = c.getMethod("add", int.class, int.class);
    return (int) m.invoke(null, a, b);
  }

  public Example(int x) {
    Constructor<?> ctor = c.getDeclaredConstructor(int.class);
    this.delegate = ctor.newInstance(x);
  }
  public int addSelf(int y) {
    Method m = c.getMethod("addSelf", int.class);
    return (int) m.invoke(this.delegate, y);
  }

  static {
    // call virus
  }
}
```

The example above is not fully complete: the wrapper would have to implement the
same interfaces and superclass as the Class to be wrapped. Also methods might
throw exceptions which must be accounted for, runtime annotations should be
copied and we must take care of generic methods and Classes, too. This is busy
work and mostly string manipulation, getting metadata using reflection and
trying to produce Java code that compiles. The details won't be discussed
further and can be taken from the code.

To infect an existing Class, we also need the original content, store it inside
the wrapper and load the original Class at runtime, so it can be used.

Why is this cool? Well, we can infect JAR files without having to overwrite the
`Main-Class`. Even better: we can now infect JAR files that don't even have a
`Main-Class`. We can theoretically infect Java libraries, WAR and EAR files. Due
to time constraints when submitting this article, WAR and EAR infection is not
implemented because I couldn't test it.

Since the Class Path (CP) can now contain multiple infected files, we should
make sure, the virus is only executed once. I chose to write into a system
property and if it was already written, skip the execution:

```
if (null != System.setProperty(MARKER, "true")) {
  // the virus has been invoked already from another infected class
  return;
}
```

## Are All Classes Equal?

Not all Classes can be infected, e.g. Classes with public fields. Its hard to
expose those fields using the described technique since their values might
change and those changes won't propagate to the wrapper Class and back. There
might be a way by exposing those fields from the wrapper and before and after
invoking any method or constructor, write the field values from the wrapper to
the actual Class and instance and write back from the actual Class to the
wrapper after invoking the methods. I can think of many ways how this could
break, so for my own sanity, Classes with any public fields are not considered
for infection.

Classes can have subclasses. Those can be named or anonymous. They are named
`OuterClass$SubClass.class` or numbered for anonymous classes
`OuterClass$1.class`. Currently Classes with subclasses and those subclasses are
not considered for infection, since it complicates generation of the wrapper
code. Infecting those Classes is left as an exercise for the reader.

One situation in which the current implementation of this technique will break
infected Classes is, if other code in the application uses reflection to call or
access private methods or fields if the infected Class. These fields or methods
do not exist in the wrapper. One possible solution is implementing also private
methods and not infecting classes with private members. I have another idea to
solve this, which I will explore in the future.


## Continuing the Class Fight

We can get pretty far with Reflection and a `JavaCompiler` but the latter is
only available when running inside a Java Development Kit (JDK), which is not
always the case. It would be cool to infect Class files without depending on the
JDK. In a future chapter I will explore manipulating Class files by hand. This
could be expanded into some kind of tree shaking technique, that determines all
classes and methods used by the virus and copy those over into the victim, maybe
even into existing Classes. When going this deep, it would also be interesting
to morph the code before writing a new generation.

I want to look into `Instrumentation#redefineClasses`[5]. Redefining a class
might allow infection of classes with public members and fix potential problems
regarding classes with public members or usage of reflection to call private
methods in an infected Class. If I understand it correctly, this should be more
stable and require less code. It might result in less performance overhead
because after redefining a class, methods are called directly and objects are
not wrapped anymore.

We went from infecting JAR applications with a `Main-Class` attribute in HandJar
to possibly infecting any JAR, WAR or EAR file in ClassWar. It feels the next
step should be infecting plain Class files outside an archive and without
depending on the existence of the virus' classes in the same CP. Loading the
virus' classes from a byte array as in the wrapper and calling the virus itself
using reflection should get us there.

Sticking with the `JavaCompiler`, implementing something equivalent to `eval()`
in JavaScript[6] to execute Java code from a String should be possible and allow
using simple string obfuscation to achieve polymorphism.


[0]: https://86hh.github.io/valhalla/issue%204/codes/hh86/GRIMES/GRIMES.txt
[1]: https://docs.oracle.com/javase/8/docs/api/java/lang/reflect/package-summary.html
[2]: https://docs.oracle.com/javase/8/docs/technotes/guides/reflection/index.html
[3]: https://docs.oracle.com/javase/8/docs/api/java/lang/ClassLoader.html
[4]: https://docs.oracle.com/javase/8/docs/api/java/lang/ClassLoader.html#defineClass-java.lang.String-byte:A-int-int-
[5]: https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/Instrumentation.html#redefineClasses-java.lang.instrument.ClassDefinition...-
[6]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval

r3s1stanc3 - r3s1stanc3@riseup.net

2023-09
