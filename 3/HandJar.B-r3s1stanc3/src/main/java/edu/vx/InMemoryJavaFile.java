package edu.vx;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import javax.tools.SimpleJavaFileObject;

/**
 * {@link javax.tools.JavaFileObject} that holds its contents in-memory. This can be used to hold
 * Java source and class files for compilation in memory without them ever touching the disk.
 */
public class InMemoryJavaFile extends SimpleJavaFileObject {
  private byte[] content;

  public InMemoryJavaFile(String name, Kind kind) {
    this(name, new byte[0], kind);
  }

  public InMemoryJavaFile(String name, String content) {
    this(name, content.getBytes(StandardCharsets.UTF_8), Kind.SOURCE);
  }

  public InMemoryJavaFile(String name, byte[] content, Kind kind) {
    super(URI.create("string:///" + InMemoryFileManager.key(kind, name)), kind);
    this.content = content;
  }

  @Override
  public InputStream openInputStream() {
    return new ByteArrayInputStream(this.content);
  }

  @Override
  public OutputStream openOutputStream() {
    return new ByteArrayOutputStream() {
      @Override
      public void close() throws IOException {
        InMemoryJavaFile.this.content = this.toByteArray();
        super.close();
      }
    };
  }

  @Override
  public CharSequence getCharContent(boolean ignoreEncodingErrors) {
    return new String(this.content, StandardCharsets.UTF_8);
  }

  public byte[] content() {
    return content.clone();
  }
}
