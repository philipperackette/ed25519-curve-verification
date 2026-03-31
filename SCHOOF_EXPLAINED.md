# Schoof's Algorithm Explained

*A pedagogical walkthrough: what each computation does, why the algorithm works, and why it is exponentially faster than exhaustive counting.*

---

## 1. Notation and conventions

Before discussing the algorithm, let us fix the notation.

**Prime field.**
Let `p` be a prime number. The finite field with `p` elements is denoted **F_p**.

**Elliptic curve.**
We consider a curve in short Weierstrass form over F_p:

```
E : Y² = X³ + aX + b
```

where the discriminant is nonzero.

**Algebraic closure.**
The symbol `F̄_p` denotes the algebraic closure of `F_p`. It contains all finite extensions `F_(p^n)` and may be viewed informally as

`F̄_p = ⋃_(n≥1) F_(p^n)`.

An element of `F̄_p` is an element that satisfies some nonzero polynomial with coefficients in `F_p`; such an element is called **algebraic** over `F_p`. Equivalently, every nonconstant polynomial with coefficients in `F_p` splits completely over `F̄_p`.

**Rational points.**
More generally, if `K` is a field containing the coefficients of the curve, the notation `E(K)` means the set of points of the curve whose coordinates lie in `K`, together with the point at infinity **O**.

Thus:
- `E(F_p)` is the set of points defined over the base field `F_p`;
- `E(F̄_p)` is the set of points defined over the algebraic closure.

The points in `E(F_p)` are called the `F_p`-rational points of the curve. In this context, “rational” does not mean “rational number”: it means “defined over the field under consideration.”

Example: a point may fail to belong to `E(F_p)` because one of its coordinates is not in `F_p`, but still belong to `E(F_(p^2))` or another extension field. Thus `E(F_p)` is the set of points defined over the base field, while `E(F̄_p)` contains all points defined over all finite extensions.

This distinction is fundamental for Schoof's algorithm. The quantity to be counted is `#E(F_p)`, the number of points defined over the base field, whereas the torsion subgroups `E[l]` are naturally studied inside `E(F̄_p)`.

Equivalently, the `F_p`-rational points are exactly the points fixed by the Frobenius endomorphism.

**Scalar multiplication.**
For a point P on the curve and an integer m, the notation `[m]P` means the sum of P with itself m times under the group law. In particular, `[0]P = O`.

**Torsion points.**
A point `P` on the curve is called a torsion point if there exists a positive integer `m` such that `[m]P = O`. In other words, a torsion point is a point of finite order.

For a prime `l ≠ p`, the **l-torsion subgroup** is the set of all points (possibly defined over extension fields of `F_p`) annihilated by scalar multiplication by `l`:

```
E[l] = { P ∈ E(F̄_p) : [l]P = O }
```

This subgroup is isomorphic to `(Z/lZ)²` and has exactly `l²` elements. It can be viewed as a two-dimensional vector space over the field with `l` elements.

This is why torsion points are so important in Schoof's algorithm: on `E[l]`, scalar multiplication depends only on residues modulo `l`, so the huge integer `p` collapses to `p mod l`, and the unknown trace `t` can also be read modulo `l`.

**Frobenius endomorphism.**
The map `φ : (x, y) ↦ (x^p, y^p)` is an endomorphism of the curve. It fixes exactly the points defined over F_p.

---

## 2. The point-counting problem

The central quantity is `#E(F_p)`, the number of rational points on the curve.

The integer `t` defined by

```
#E(F_p) = p + 1 - t
```

is called the **trace of Frobenius**. **Hasse's theorem** states that it satisfies

```
|t| ≤ 2√p
```

Point counting is therefore equivalent to computing this integer `t`.

---

## 3. Why exhaustive counting is hopeless

The naive method would loop over every x ∈ F_p, compute `x³ + ax + b`, test whether the result is a square, and count accordingly.

This costs on the order of `p` operations — exponential in the bitlength of p. For a cryptographic prime like `p = 2²⁵⁵ - 19`, that is roughly 10⁷⁷ field operations. Completely infeasible.

---

## 4. The Frobenius identity

The algorithm rests on the following structural theorem.

**Theorem.** *For an elliptic curve E/F_p, the Frobenius endomorphism satisfies:*

```
φ² - [t]φ + [p] = 0       in End(E)
```

Here `End(E)` denotes the ring of endomorphisms of the elliptic curve, that is, the maps from `E` to itself that respect the group structure.

Applied to any point P on the curve, this becomes:

```
φ²(P) + [p]P = [t]φ(P)
```

This identity is the algebraic engine of Schoof's algorithm. It relates the unknown trace t to concrete operations on curve points.

---

## 5. Computing t modulo small primes

Instead of finding the full integer t directly, Schoof computes `t mod l` for many small primes l.

Once enough congruences are known, the **Chinese Remainder Theorem** reconstructs t. If the product `M = ∏ l_i` exceeds `4√p`, then Hasse's bound guarantees that the corresponding residue class contains a unique admissible integer t.

**Proposition.** *If M > 4√p, then at most one integer t with |t| ≤ 2√p lies in any given residue class modulo M.*

*Proof.* If `t₁ ≡ t₂ (mod M)`, then M divides `t₁ - t₂`. But `|t₁ - t₂| ≤ 4√p < M`, so `t₁ = t₂`. ∎

---

## 6. Why the l-torsion is the right place to work

On the l-torsion subgroup E[l], scalar multiplication depends only on residues modulo l:

**Lemma.** *If P ∈ E[l] and m ≡ n (mod l), then [m]P = [n]P.*

*Proof.* Write `m - n = lk`. Then `[m]P - [n]P = [lk]P = [k]([l]P) = [k]O = O`. ∎

Therefore, on E[l], the Frobenius identity

```
φ²(P) + [p]P = [t]φ(P)
```

depends only on `q = p mod l` and `τ = t mod l`:

```
φ²(P) + [q]P = [τ]φ(P)
```

The global point-counting problem thus becomes a local endomorphism problem on the small torsion module E[l].

---

## 7. Division polynomials and the generic torsion point

For an odd prime l, the **l-th division polynomial** ψ_l is a univariate polynomial whose roots are exactly the x-coordinates of the nonzero l-torsion points. Its degree is `(l² - 1)/2`.

Instead of enumerating the torsion points, Schoof works in the **quotient ring**:

```
R_l = F_p[X] / (ψ_l(X))
```

In this ring, the residue class of `X` represents the x-coordinate of a generic nonzero `l`-torsion point. This is one of the decisive conceptual tricks: rather than handling concrete torsion points, the algorithm works symbolically with a universal representative modulo the torsion relation.

A useful analogy is this: instead of choosing one explicit `l`-torsion point and computing with its coordinates, we let `X` stand for the x-coordinate of a "generic" nonzero `l`-torsion point, subject only to the relation `ψ_l(X)=0`.

In this way, one symbolic computation modulo `ψ_l` simultaneously captures what would otherwise have to be checked point by point over extension fields.

---

## 8. Meaning of each main computation

### Computing ψ_l

This constructs the algebraic environment `R_l = F_p[X] / (ψ_l)`.

*Purpose:* to encode the generic nonzero l-torsion point. Without this quotient ring, one would need to work with individual torsion points in extension fields.

### Computing X^p mod ψ_l

Since `φ(x, y) = (x^p, y^p)`, the polynomial `X^p mod ψ_l` represents the x-coordinate of φ(P) for the generic torsion point.

*Purpose:* to model the action of Frobenius on the x-coordinate.

### Computing X^(p²) mod ψ_l

Likewise, `X^(p²) mod ψ_l` represents the x-coordinate of φ²(P).

*Purpose:* to prepare the left-hand side of the Frobenius identity.

### Reducing p modulo l

One computes `q ≡ p (mod l)`. Then on E[l], the scalar multiplication `[p]P` becomes `[q]P`.

*Purpose:* to replace multiplication by the enormous integer p with multiplication by the small residue q. This is a dramatic cost reduction.

### Computing f(X)^((p-1)/2)

Let `f(X) = X³ + aX + b`. Because the curve equation is `Y² = f(X)`, we get:

```
Y^p = Y · (Y²)^((p-1)/2) = Y · f(X)^((p-1)/2)
```

*Purpose:* to recover the multiplicative factor that turns Y into Y^p. The x-coordinate alone cannot distinguish a point from its inverse; the y-factor resolves this ambiguity.

### Computing f(X)^((p²-1)/2)

Similarly, `Y^(p²) = Y · f(X)^((p²-1)/2)`.

*Purpose:* to describe the y-factor of φ²(P).

### Testing candidate residues τ

The algorithm searches for candidates τ ∈ {1, ..., (l-1)/2} such that:

```
φ²(P) + [q]P = ±[τ]φ(P)
```

Only half the range needs testing, because the x-coordinate test sees only ±τ (a point and its inverse share the same x-coordinate on a Weierstrass curve).

### The x-match

When the algorithm finds that the x-coordinate of `φ²(P) + [q]P` equals the x-coordinate of `[τ]φ(P)`, it has shown that:

```
φ²(P) + [q]P = ±[τ]φ(P)
```

The sign ambiguity is unavoidable: on a Weierstrass curve, both `(x, y)` and `(x, -y)` have the same x-coordinate.

### The sign check

The sign is resolved by comparing the y-factors. If the sign is positive, then `t ≡ τ (mod l)`. If the sign is negative, then `t ≡ -τ (mod l)`.

This is not an implementation quirk — it is a structural consequence of the geometry of the curve.

---

## 9. Why Schoof is so much faster

The efficiency gain comes from a complete change of viewpoint.

**Naive counting** costs `O(p)` operations, which is exponential in log(p).

**Schoof's algorithm** works in quotient rings `F_p[X] / (ψ_l)`, uses symbolic Frobenius computations, determines t mod l locally for each small prime l, and reconstructs the full trace via CRT. The overall complexity is polynomial in log(p).

The practical cost still rises as l increases, because the degree of ψ_l grows quadratically: `deg(ψ_l) = (l² - 1)/2`. But this remains incomparably smaller than anything proportional to p itself.

For Ed25519 (`p ≈ 2²⁵⁵`), the algorithm needs primes up to about l = 103 and processes 27 primes total. The polynomial degrees reach a few thousand — large, but astronomically smaller than 2²⁵⁵.

---

## 10. Summary

| Computation | Mathematical role |
|---|---|
| ψ_l | Encodes the generic nonzero l-torsion point |
| X^p mod ψ_l | x-coordinate of φ(P) |
| X^(p²) mod ψ_l | x-coordinate of φ²(P) |
| q = p mod l | Reduces [p] to a small scalar on E[l] |
| f(X)^((p-1)/2) | y-factor of φ(P) |
| f(X)^((p²-1)/2) | y-factor of φ²(P) |
| Candidate τ search | Finds t mod l up to sign |
| x-match | Proves equality up to sign |
| Sign check | Distinguishes +τ from -τ |
| CRT accumulation | Reconstructs the global trace t |

---

## 11. Conclusion

Schoof's algorithm does not attack the point-counting problem head-on. It uses the arithmetic structure of the Frobenius endomorphism, the finite-dimensional algebra of the torsion subgroups, and the symbolic encoding provided by division polynomials to extract the trace of Frobenius one residue at a time.

This is why it works, and this is why it is dramatically more efficient than exhaustive counting.

---

*For a deeper treatment of applied elliptic curve cryptography — including threshold signatures, operational security, and practical implementations — see [Quorum Cryptography on Tails OS](https://www.amazon.fr/dp/B0GLGC8GWP) by Philippe Rackette.*
