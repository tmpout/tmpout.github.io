package edu.vx;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class HandJarTest {
  private static final String[] MANIFEST =
      new String[] {"Foo: Bar", "Baz: qux", "Bar: Foo", "Blub: This: is: Strange"};

  @Test
  public void lines() {
    String differentLineSeparators = "foo\nbar\r\nbaz\rqux";
    assertEquals(4, HandJar.lines(differentLineSeparators).length);
  }

  @Test
  public void readManifest() {
    assertEquals("Bar", HandJar.readManifest(MANIFEST, "Foo"));
    // reading a missing key returns null
    assertNull(HandJar.readManifest(MANIFEST, "MissingKey"));
    assertEquals("This: is: Strange", HandJar.readManifest(MANIFEST, "Blub"));
    // test case insensitivity
    assertEquals("Bar", HandJar.readManifest(MANIFEST, "fOo"));
  }

  @Test
  public void writeManifest() {
    String[] manifest = HandJar.writeManifest(MANIFEST, "Foo", "Foobar: BazFoo");
    assertTrue(Arrays.asList(manifest).contains("Foo: Foobar: BazFoo"));
  }

  @Test
  public void writeManifestAddMissing() {
    String[] manifest = HandJar.writeManifest(MANIFEST, "Not-Present", "Some Value");
    assertTrue(Arrays.asList(manifest).contains("Not-Present: Some Value"));
  }

  @Test
  public void joinManifest() {
    String manifest = HandJar.joinManifest(MANIFEST);
    for (String line : MANIFEST) {
      assertTrue(manifest.contains(line));
    }
    assertTrue(manifest.endsWith("\n"));
  }
}
