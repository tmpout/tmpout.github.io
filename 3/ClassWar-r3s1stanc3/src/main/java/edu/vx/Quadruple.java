package edu.vx;

public class Quadruple<A, B, C, D> extends Pair<A, B> {
  public final C c;
  public final D d;

  public Quadruple(A a, B b, C c, D d) {
    super(a, b);
    this.c = c;
    this.d = d;
  }
}
