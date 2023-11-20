package edu.vx;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

@Retention(RUNTIME)
@Target({
  ElementType.TYPE,
  ElementType.FIELD,
  ElementType.METHOD,
  ElementType.PARAMETER,
  ElementType.CONSTRUCTOR,
  ElementType.LOCAL_VARIABLE,
  ElementType.ANNOTATION_TYPE,
  ElementType.PACKAGE,
  ElementType.TYPE_PARAMETER,
  ElementType.TYPE_USE
})
public @interface TestAnnotation {
  String value();

  double foo() default 3.;

  TestEnum bar() default TestEnum.B;

  Class<?> cls() default Object.class;

  TestAnnotationInner ann() default @TestAnnotationInner;
}
