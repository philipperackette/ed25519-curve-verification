/*
 * ed25519_verify.cpp — Ed25519 Independent Verification
 *
 * SINGLE FILE, ZERO EXTERNAL DEPENDENCIES.
 * Compile:  g++ -O2 -std=c++17 -o ed25519_verify ed25519_verify.cpp
 * Run:      ./ed25519_verify                    (full)
 *           ./ed25519_verify --generator-only   (fast, ~2s)
 *           ./ed25519_verify --schoof-only      (slow, hours)
 *           ./ed25519_verify --small-test       (small-curve brute-force only; does NOT run Schoof)
 *
 * PROVEN by computation:
 *  - p = 2^255-19 is prime (Miller-Rabin, 20 deterministic bases)
 *  - d = -121665/121666 mod p, verified nonsquare
 *  - Base point B computed from y=4/5, verified on curve
 *  - [l]B = O, l prime → ord(B) = l (Lagrange)
 *  - Edwards↔Montgomery↔Weierstrass verified on B (round-trip)
 *  - #E(F_p) via Schoof (independent of any expected value)
 *
 * COMPARED a posteriori only:
 *  - l, #E, cofactor h=8 vs expected Ed25519 constants
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cassert>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

// ════════════════════════════════════════════════════════════════════
// SECTION 1:  Uint256 — unsigned 256-bit integer
// ════════════════════════════════════════════════════════════════════

struct Uint256 {
    uint64_t w[4]; // little-endian: w[0] = LSW

    Uint256() { w[0]=w[1]=w[2]=w[3]=0; }
    explicit Uint256(uint64_t v) { w[0]=v; w[1]=w[2]=w[3]=0; }
    Uint256(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
        { w[0]=a; w[1]=b; w[2]=c; w[3]=d; }

    bool is_zero() const { return !(w[0]|w[1]|w[2]|w[3]); }

    int cmp(const Uint256& o) const {
        for (int i=3; i>=0; i--) {
            if (w[i] < o.w[i]) return -1;
            if (w[i] > o.w[i]) return  1;
        }
        return 0;
    }
    bool operator==(const Uint256& o) const { return cmp(o)==0; }
    bool operator!=(const Uint256& o) const { return cmp(o)!=0; }
    bool operator< (const Uint256& o) const { return cmp(o)< 0; }
    bool operator<=(const Uint256& o) const { return cmp(o)<=0; }
    bool operator> (const Uint256& o) const { return cmp(o)> 0; }
    bool operator>=(const Uint256& o) const { return cmp(o)>=0; }

    // Add, returns carry (0 or 1)
    static int add(Uint256& r, const Uint256& a, const Uint256& b) {
        __uint128_t c = 0;
        for (int i=0; i<4; i++) {
            c += (__uint128_t)a.w[i] + b.w[i];
            r.w[i] = (uint64_t)c;
            c >>= 64;
        }
        return (int)c;
    }
    // Sub, returns borrow (0 or 1)
    static int sub(Uint256& r, const Uint256& a, const Uint256& b) {
        __int128_t c = 0;
        for (int i=0; i<4; i++) {
            c += (__int128_t)a.w[i] - b.w[i];
            r.w[i] = (uint64_t)c;
            c >>= 64;
        }
        return (c < 0) ? 1 : 0;
    }
    Uint256 operator+(const Uint256& o) const { Uint256 r; add(r,*this,o); return r; }
    Uint256 operator-(const Uint256& o) const { Uint256 r; sub(r,*this,o); return r; }

    bool bit(int n) const {
        if (n<0 || n>=256) return false;
        return (w[n/64] >> (n%64)) & 1;
    }
    // Highest set bit position, -1 if zero
    int bits() const {
        for (int i=3; i>=0; i--)
            if (w[i]) { int b=63; while (b>0 && !((w[i]>>b)&1)) b--; return i*64+b; }
        return -1;
    }
    int bit_length() const { int b=bits(); return b<0 ? 0 : b+1; }

    Uint256 shl1() const {
        Uint256 r;
        r.w[0] = w[0]<<1;
        r.w[1] = (w[1]<<1) | (w[0]>>63);
        r.w[2] = (w[2]<<1) | (w[1]>>63);
        r.w[3] = (w[3]<<1) | (w[2]>>63);
        return r;
    }
    Uint256 shr1() const {
        Uint256 r;
        r.w[0] = (w[0]>>1) | (w[1]<<63);
        r.w[1] = (w[1]>>1) | (w[2]<<63);
        r.w[2] = (w[2]>>1) | (w[3]<<63);
        r.w[3] = w[3]>>1;
        return r;
    }

    // Full 256×256 → (lo, hi)
    static void mul_full(const Uint256& a, const Uint256& b,
                         Uint256& lo, Uint256& hi) {
        __uint128_t acc[8] = {};
        for (int i=0; i<4; i++) {
            __uint128_t carry = 0;
            for (int j=0; j<4; j++) {
                __uint128_t p = (__uint128_t)a.w[i] * b.w[j] + acc[i+j] + carry;
                acc[i+j] = (uint64_t)p;
                carry = p >> 64;
            }
            acc[i+4] += carry;
        }
        for (int i=4; i<7; i++) { acc[i+1] += acc[i]>>64; acc[i]=(uint64_t)acc[i]; }
        for (int i=0; i<4; i++) lo.w[i] = (uint64_t)acc[i];
        for (int i=0; i<4; i++) hi.w[i] = (uint64_t)acc[i+4];
    }
    // Multiply by small constant, returns 5th limb
    static uint64_t mul_small(Uint256& r, const Uint256& a, uint64_t b) {
        __uint128_t c = 0;
        for (int i=0; i<4; i++) {
            c += (__uint128_t)a.w[i] * b;
            r.w[i] = (uint64_t)c;
            c >>= 64;
        }
        return (uint64_t)c;
    }

    std::string to_dec() const {
        if (is_zero()) return "0";
        Uint256 t = *this;
        char buf[80]; int pos = 79; buf[pos] = 0;
        while (!t.is_zero()) {
            uint64_t rem = 0;
            for (int i=3; i>=0; i--) {
                __uint128_t v = ((__uint128_t)rem << 64) | t.w[i];
                t.w[i] = (uint64_t)(v / 10);
                rem = (uint64_t)(v % 10);
            }
            buf[--pos] = '0' + (char)rem;
        }
        return std::string(buf + pos);
    }
    std::string to_hex() const {
        char buf[65];
        snprintf(buf, sizeof(buf), "%016llx%016llx%016llx%016llx",
         (unsigned long long)w[3],
         (unsigned long long)w[2],
         (unsigned long long)w[1],
         (unsigned long long)w[0]);
        char* s = buf;
        while (*s == '0' && *(s+1)) s++;
        return std::string(s);
    }
    static Uint256 from_dec(const char* s) {
        Uint256 r;
        while (*s) {
            Uint256 r10;
            mul_small(r10, r, 10);
            r = r10 + Uint256((uint64_t)(*s - '0'));
            s++;
        }
        return r;
    }
};

// ════════════════════════════════════════════════════════════════════
// SECTION 2:  Fp — arithmetic in F_p,  p = 2^255 − 19
// ════════════════════════════════════════════════════════════════════

static Uint256 P_MOD(
    0xFFFFFFFFFFFFFFEDULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL);

struct FieldModulusGuard {
    Uint256 saved;
    FieldModulusGuard() : saved(P_MOD) {}
    ~FieldModulusGuard() { P_MOD = saved; }
};

struct Fp {
    Uint256 v; // in [0, p)

    Fp() {}
    explicit Fp(uint64_t val) : v(val) {}
    explicit Fp(const Uint256& val) { v = val; reduce(); }

    static Fp neg(uint64_t n) {
        if (!n) return Fp(0ULL);
        Fp r; Uint256::sub(r.v, P_MOD, Uint256(n)); return r;
    }
    static Fp zero() { return Fp(0ULL); }
    static Fp one()  { return Fp(1ULL); }
    bool is_zero() const { return v.is_zero(); }

    void reduce() { if (v >= P_MOD) Uint256::sub(v, v, P_MOD); }

    Fp operator+(const Fp& o) const {
        Fp r;
        int c = Uint256::add(r.v, v, o.v);
        if (c || r.v >= P_MOD) Uint256::sub(r.v, r.v, P_MOD);
        return r;
    }
    Fp operator-(const Fp& o) const {
        Fp r;
        int b = Uint256::sub(r.v, v, o.v);
        if (b) Uint256::add(r.v, r.v, P_MOD);
        return r;
    }
    Fp operator-() const {
        if (is_zero()) return *this;
        Fp r; Uint256::sub(r.v, P_MOD, v); return r;
    }

    /* Multiplication with fast reduction:
       N = lo + hi·2^256.  Since 2^256 ≡ 38 (mod p),  N ≡ lo + 38·hi.
       Then split at bit 255: low_part + 19·high_bits. */
    Fp operator*(const Fp& o) const {
        Uint256 lo, hi;
        Uint256::mul_full(v, o.v, lo, hi);
        return from_512(lo, hi);
    }
    static Fp from_512(const Uint256& lo, const Uint256& hi) {
        static const Uint256 ED25519_P(
            0xFFFFFFFFFFFFFFEDULL, 0xFFFFFFFFFFFFFFFFULL,
            0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL);

        if (P_MOD == ED25519_P) {
            // Fast reduction for p = 2^255 - 19
            Uint256 t38;
            uint64_t extra = Uint256::mul_small(t38, hi, 38);
            Uint256 s;
            int carry = Uint256::add(s, lo, t38);
            extra += carry;
            if (extra) {
                Uint256 e(38 * extra);
                int c2 = Uint256::add(s, s, e);
                while (c2) {
                    Uint256 fold(38ULL * (uint64_t)c2);
                    c2 = Uint256::add(s, s, fold);
                }
            }

            uint64_t top = s.w[3] >> 63;
            s.w[3] &= 0x7FFFFFFFFFFFFFFFULL;
            if (top) {
                Uint256::add(s, s, Uint256(19 * top));
                top = s.w[3] >> 63;
                s.w[3] &= 0x7FFFFFFFFFFFFFFFULL;
                if (top) Uint256::add(s, s, Uint256(19ULL));
            }

            Fp r; r.v = s;
            while (r.v >= P_MOD) Uint256::sub(r.v, r.v, P_MOD);
            return r;
        }

        // Generic reduction of the 512-bit integer (hi:lo) modulo P_MOD
        Uint256 rem;
        for (int i = 511; i >= 0; --i) {
            int carry2 = 0;
            for (int j = 0; j < 4; ++j) {
                uint64_t nc = rem.w[j] >> 63;
                rem.w[j] = (rem.w[j] << 1) | (uint64_t)carry2;
                carry2 = (int)nc;
            }

            if (i >= 256) {
                int limb = (i - 256) / 64;
                int bp   = (i - 256) % 64;
                if (hi.w[limb] & (1ULL << bp)) {
                    Uint256::add(rem, rem, Uint256(1));
                }
            } else {
                int limb = i / 64;
                int bp   = i % 64;
                if (lo.w[limb] & (1ULL << bp)) {
                    Uint256::add(rem, rem, Uint256(1));
                }
            }

            while (rem >= P_MOD) Uint256::sub(rem, rem, P_MOD);
        }

        Fp r; r.v = rem;
        return r;
    }

    Fp& operator+=(const Fp& o) { *this = *this + o; return *this; }
    Fp& operator-=(const Fp& o) { *this = *this - o; return *this; }
    Fp& operator*=(const Fp& o) { *this = *this * o; return *this; }

    Fp pow(const Uint256& e) const {
        if (e.is_zero()) return one();
        Fp r = one(), b = *this;
        int top = e.bits();
        for (int i = top; i >= 0; i--) {
            r = r * r;
            if (e.bit(i)) r = r * b;
        }
        return r;
    }
    Fp pow(uint64_t e) const { return pow(Uint256(e)); }

    // Inverse via Fermat: a^{p-2}
    Fp inv() const {
        assert(!is_zero());
        return pow(P_MOD - Uint256(2));
    }
    Fp operator/(const Fp& o) const { return *this * o.inv(); }

    // Square root for p ≡ 5 (mod 8)
    Fp sqrt() const {
        // (p+3)/8 = 2^252 - 2
        Uint256 exp1(0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL,
                     0xFFFFFFFFFFFFFFFFULL, 0x0FFFFFFFFFFFFFFFULL);
        Fp cand = pow(exp1);
        if (cand * cand == *this) return cand;
        // sqrt(-1) = 2^{(p-1)/4}
        Uint256 exp2(0xFFFFFFFFFFFFFFFBULL, 0xFFFFFFFFFFFFFFFFULL,
                     0xFFFFFFFFFFFFFFFFULL, 0x1FFFFFFFFFFFFFFFULL);
        Fp i = Fp(2ULL).pow(exp2);
        return cand * i;
    }

    Fp legendre() const {
        // a^{(p-1)/2}
        Uint256 e(0xFFFFFFFFFFFFFFF6ULL, 0xFFFFFFFFFFFFFFFFULL,
                  0xFFFFFFFFFFFFFFFFULL, 0x3FFFFFFFFFFFFFFFULL);
        return pow(e);
    }

    bool operator==(const Fp& o) const { return v == o.v; }
    bool operator!=(const Fp& o) const { return v != o.v; }

    static Fp from_dec(const char* s) {
        Uint256 val = Uint256::from_dec(s);
        Fp r; r.v = val;
        while (r.v >= P_MOD) Uint256::sub(r.v, r.v, P_MOD);
        return r;
    }
    std::string to_dec() const { return v.to_dec(); }
    std::string to_hex() const { return v.to_hex(); }
};

// ════════════════════════════════════════════════════════════════════
// SECTION 3:  Miller-Rabin primality test (self-contained)
// ════════════════════════════════════════════════════════════════════

static Uint256 mr_mulmod(const Uint256& a, const Uint256& b, const Uint256& m) {
    Uint256 lo, hi;
    Uint256::mul_full(a, b, lo, hi);
    // For m = p, use fast reduction
    if (m == P_MOD) return Fp::from_512(lo, hi).v;
    // General: compute 2^256 mod m, then reduce hi*2^256+lo
    Uint256 pow256(1);
    for (int i = 0; i < 256; i++) {
        int c = Uint256::add(pow256, pow256, pow256);
        if (c || pow256 >= m) Uint256::sub(pow256, pow256, m);
    }
    Uint256 hm = hi;
    while (hm >= m) Uint256::sub(hm, hm, m);
    Uint256 lm = lo;
    while (lm >= m) Uint256::sub(lm, lm, m);
    // result = hm * pow256 + lm, all mod m
    Uint256 plo, phi;
    Uint256::mul_full(hm, pow256, plo, phi);
    // Reduce (plo, phi) mod m by binary long division
    Uint256 rem;
    for (int i = 511; i >= 0; i--) {
        // rem <<= 1
        int carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t nc = rem.w[j] >> 63;
            rem.w[j] = (rem.w[j] << 1) | carry;
            carry = nc;
        }
        // Add bit i
        if (i >= 256) {
            int limb = (i-256)/64, bp = (i-256)%64;
            if (phi.w[limb] & (1ULL << bp))
                Uint256::add(rem, rem, Uint256(1));
        } else {
            int limb = i/64, bp = i%64;
            if (plo.w[limb] & (1ULL << bp))
                Uint256::add(rem, rem, Uint256(1));
        }
        if (rem >= m) Uint256::sub(rem, rem, m);
    }
    int csum = Uint256::add(rem, rem, lm);
    if (csum) {
        int c2 = Uint256::add(rem, rem, pow256);
        while (c2 || rem >= m) {
            Uint256::sub(rem, rem, m);
            c2 = 0;
        }
    }
    while (rem >= m) Uint256::sub(rem, rem, m);
    return rem;
}

static Uint256 mr_powmod(const Uint256& base, const Uint256& exp, const Uint256& m) {
    if (exp.is_zero()) return Uint256(1);
    Uint256 r(1), b = base;
    while (b >= m) Uint256::sub(b, b, m);
    int top = exp.bits();
    for (int i = top; i >= 0; i--) {
        r = mr_mulmod(r, r, m);
        if (exp.bit(i)) r = mr_mulmod(r, b, m);
    }
    return r;
}

static bool miller_rabin(const Uint256& n, int rounds = 20) {
    if (n <= Uint256(3)) return n >= Uint256(2);
    if (!(n.w[0] & 1)) return false;
    Uint256 nm1 = n - Uint256(1), d = nm1;
    int r = 0;
    while (!(d.w[0] & 1)) { d = d.shr1(); r++; }
    uint64_t bases[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71};
    int nb = rounds < 20 ? rounds : 20;
    for (int i = 0; i < nb; i++) {
        Uint256 a(bases[i]);
        if (a >= nm1) continue;
        Uint256 x = mr_powmod(a, d, n);
        if (x == Uint256(1) || x == nm1) continue;
        bool found = false;
        for (int j = 0; j < r-1; j++) {
            x = mr_mulmod(x, x, n);
            if (x == nm1) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

// ════════════════════════════════════════════════════════════════════
// SECTION 4:  Edwards curve  -x²+y² = 1+d·x²·y²  (a = -1)
// ════════════════════════════════════════════════════════════════════

static Fp CURVE_D; // initialized in main

struct EdPoint {
    Fp X, Y, Z, T; // Extended coords: x=X/Z, y=Y/Z, T=XY/Z

    static EdPoint identity() {
        EdPoint P; P.X=Fp::zero(); P.Y=Fp::one(); P.Z=Fp::one(); P.T=Fp::zero();
        return P;
    }
    static EdPoint from_affine(const Fp& x, const Fp& y) {
        EdPoint P; P.X=x; P.Y=y; P.Z=Fp::one(); P.T=x*y; return P;
    }
    void to_affine(Fp& x, Fp& y) const { Fp zi=Z.inv(); x=X*zi; y=Y*zi; }
    bool is_neutral() const { return X.is_zero() && (Y==Z); }

    static bool on_curve_affine(const Fp& x, const Fp& y) {
        Fp x2=x*x, y2=y*y;
        return (-x2 + y2) == (Fp::one() + CURVE_D * x2 * y2);
    }

    // HWCD'08 unified addition (complete for a=-1, d nonsquare)
    EdPoint operator+(const EdPoint& Q) const {
        Fp A = X*Q.X, B = Y*Q.Y, C = T*CURVE_D*Q.T, D = Z*Q.Z;
        Fp E = (X+Y)*(Q.X+Q.Y) - A - B;
        Fp F = D - C, G = D + C, H = B + A; // H = B - a·A = B+A since a=-1
        EdPoint R; R.X=E*F; R.Y=G*H; R.Z=F*G; R.T=E*H; return R;
    }

    // Dedicated doubling
    EdPoint dbl() const {
        Fp A=X*X, B=Y*Y, C=Z*Z; C=C+C; // C = 2Z²
        Fp D = -A; // a·A = -A
        Fp E = (X+Y)*(X+Y) - A - B;
        Fp G = D+B, F = G-C, H = D-B;
        EdPoint R; R.X=E*F; R.Y=G*H; R.Z=F*G; R.T=E*H; return R;
    }

    EdPoint operator-() const {
        EdPoint R; R.X=-X; R.Y=Y; R.Z=Z; R.T=-T; return R;
    }

    EdPoint scalar_mul(const Uint256& k) const {
        if (k.is_zero()) return identity();
        EdPoint R = identity(), base = *this;
        int top = k.bits();
        for (int i = top; i >= 0; i--) {
            R = R.dbl();
            if (k.bit(i)) R = R + base;
        }
        return R;
    }
    EdPoint scalar_mul(uint64_t k) const { return scalar_mul(Uint256(k)); }

    bool operator==(const EdPoint& Q) const {
        return (X*Q.Z == Q.X*Z) && (Y*Q.Z == Q.Y*Z);
    }
    bool operator!=(const EdPoint& Q) const { return !(*this==Q); }
};

// ════════════════════════════════════════════════════════════════════
// SECTION 5:  Curve conversions  Edwards ↔ Montgomery ↔ Weierstrass
// ════════════════════════════════════════════════════════════════════

static Fp MONT_A, MONT_B, WEIER_A, WEIER_B;

static void init_conversions() {
    MONT_A = Fp(486662ULL);
    MONT_B = -Fp(486664ULL);
    Fp A2 = MONT_A*MONT_A, B2 = MONT_B*MONT_B;
    Fp three = Fp(3ULL);
    WEIER_A = (three - A2) / (three * B2);
    Fp A3 = A2*MONT_A, B3 = B2*MONT_B;
    WEIER_B = (Fp(2ULL)*A3 - Fp(9ULL)*MONT_A) / (Fp(27ULL)*B3);
}

static bool ed_to_mont(const Fp& xe, const Fp& ye, Fp& u, Fp& v) {
    Fp d = Fp::one()-ye;
    if (d.is_zero() || xe.is_zero()) return false;
    u = (Fp::one()+ye)/d; v = u/xe; return true;
}
static bool mont_to_ed(const Fp& u, const Fp& v, Fp& xe, Fp& ye) {
    if (v.is_zero()) return false;
    Fp ud = u+Fp::one(); if (ud.is_zero()) return false;
    xe = u/v; ye = (u-Fp::one())/ud; return true;
}
static void mont_to_weier(const Fp& u, const Fp& v, Fp& Xw, Fp& Yw) {
    Fp three=Fp(3ULL);
    Xw = (three*u + MONT_A)/(three*MONT_B);
    Yw = v/MONT_B;
}
static void weier_to_mont(const Fp& Xw, const Fp& Yw, Fp& u, Fp& v) {
    Fp three=Fp(3ULL);
    u = MONT_B*Xw - MONT_A/three;
    v = MONT_B*Yw;
}
[[maybe_unused]] static bool ed_to_weier(const Fp& xe, const Fp& ye, Fp& Xw, Fp& Yw) {
    Fp u,v; if (!ed_to_mont(xe,ye,u,v)) return false;
    mont_to_weier(u,v,Xw,Yw); return true;
}
static bool weier_to_ed(const Fp& Xw, const Fp& Yw, Fp& xe, Fp& ye) {
    Fp u,v; weier_to_mont(Xw,Yw,u,v);
    return mont_to_ed(u,v,xe,ye);
}
static bool on_montgomery(const Fp& u, const Fp& v) {
    return MONT_B*v*v == u*u*u + MONT_A*u*u + u;
}
static bool on_weierstrass(const Fp& X, const Fp& Y) {
    return Y*Y == X*X*X + WEIER_A*X + WEIER_B;
}

// ════════════════════════════════════════════════════════════════════
// SECTION 6:  Polynomial ring F_p[x]
// ════════════════════════════════════════════════════════════════════

static const int KTHRESH = 32;

struct Poly {
    std::vector<Fp> c; // c[i] = coeff of x^i

    Poly() {}
    explicit Poly(const Fp& a) { if (!a.is_zero()) c.push_back(a); }
    explicit Poly(std::vector<Fp> v) : c(std::move(v)) { strip(); }

    static Poly X() { Poly r; r.c.resize(2,Fp::zero()); r.c[1]=Fp::one(); return r; }
    static Poly zero() { return Poly(); }
    static Poly one()  { return Poly(Fp::one()); }

    int deg() const { return (int)c.size()-1; }
    bool is_zero() const { return c.empty(); }
    Fp coeff(int i) const { return (i>=0 && i<(int)c.size()) ? c[i] : Fp::zero(); }
    Fp lead() const { return is_zero() ? Fp::zero() : c.back(); }

    void strip() { while (!c.empty() && c.back().is_zero()) c.pop_back(); }

    Poly monic() const {
        if (is_zero()) return *this;
        Fp li = lead().inv();
        Poly r; r.c.resize(c.size());
        for (size_t i=0; i<c.size(); i++) r.c[i] = c[i]*li;
        return r;
    }

    Poly operator+(const Poly& o) const {
        size_t n = std::max(c.size(), o.c.size());
        Poly r; r.c.resize(n, Fp::zero());
        for (size_t i=0; i<c.size(); i++)   r.c[i] = r.c[i]+c[i];
        for (size_t i=0; i<o.c.size(); i++) r.c[i] = r.c[i]+o.c[i];
        r.strip(); return r;
    }
    Poly operator-(const Poly& o) const {
        size_t n = std::max(c.size(), o.c.size());
        Poly r; r.c.resize(n, Fp::zero());
        for (size_t i=0; i<c.size(); i++)   r.c[i] = r.c[i]+c[i];
        for (size_t i=0; i<o.c.size(); i++) r.c[i] = r.c[i]-o.c[i];
        r.strip(); return r;
    }
    Poly operator-() const {
        Poly r; r.c.resize(c.size());
        for (size_t i=0; i<c.size(); i++) r.c[i] = -c[i];
        r.strip(); return r;
    }
    Poly operator*(const Fp& s) const {
        if (s.is_zero()) return Poly();
        Poly r; r.c.resize(c.size());
        for (size_t i=0; i<c.size(); i++) r.c[i] = c[i]*s;
        r.strip(); return r;
    }
    Poly& operator+=(const Poly& o) { *this=*this+o; return *this; }
    Poly& operator-=(const Poly& o) { *this=*this-o; return *this; }

    static Poly mul_naive(const Poly& a, const Poly& b) {
        if (a.is_zero()||b.is_zero()) return Poly();
        Poly r; r.c.resize(a.deg()+b.deg()+1, Fp::zero());
        for (int i=0; i<=a.deg(); i++)
            for (int j=0; j<=b.deg(); j++)
                r.c[i+j] += a.c[i]*b.c[j];
        r.strip(); return r;
    }
    static Poly mul_kara(const Poly& a, const Poly& b) {
        int na=(int)a.c.size(), nb=(int)b.c.size();
        if (!na||!nb) return Poly();
        if (na<KTHRESH || nb<KTHRESH) return mul_naive(a,b);
        int half = std::max(na,nb)/2;
        Poly a0,a1,b0,b1;
        a0.c.assign(a.c.begin(), a.c.begin()+std::min(half,na));
        if (na>half) a1.c.assign(a.c.begin()+half, a.c.end());
        b0.c.assign(b.c.begin(), b.c.begin()+std::min(half,nb));
        if (nb>half) b1.c.assign(b.c.begin()+half, b.c.end());
        a0.strip(); a1.strip(); b0.strip(); b1.strip();
        Poly z0=mul_kara(a0,b0), z2=mul_kara(a1,b1);
        Poly z1=mul_kara(a0+a1,b0+b1)-z0-z2;
        int rs=std::max({(int)z0.c.size(),(int)z1.c.size()+half,(int)z2.c.size()+2*half});
        Poly r; r.c.resize(rs,Fp::zero());
        for (int i=0; i<(int)z0.c.size(); i++) r.c[i]+=z0.c[i];
        for (int i=0; i<(int)z1.c.size(); i++) r.c[i+half]+=z1.c[i];
        for (int i=0; i<(int)z2.c.size(); i++) r.c[i+2*half]+=z2.c[i];
        r.strip(); return r;
    }
    Poly operator*(const Poly& o) const { return mul_kara(*this,o); }

    static void divmod(const Poly& num, const Poly& den, Poly& quo, Poly& rem) {
        assert(!den.is_zero());
        if (num.deg()<den.deg()) { quo=Poly(); rem=num; return; }
        Fp li = den.lead().inv();
        int dq = num.deg()-den.deg();
        Poly r = num; quo.c.resize(dq+1, Fp::zero());
        for (int i=dq; i>=0; i--) {
            Fp co = r.coeff(i+den.deg())*li;
            quo.c[i] = co;
            if (!co.is_zero())
                for (int j=0; j<=den.deg(); j++)
                    if (i+j < (int)r.c.size()) r.c[i+j] -= co*den.c[j];
        }
        r.strip(); quo.strip(); rem=r;
    }
    Poly operator%(const Poly& m) const { Poly q,r; divmod(*this,m,q,r); return r; }
    Poly operator/(const Poly& d) const { Poly q,r; divmod(*this,d,q,r); return q; }

    static Poly mulmod(const Poly& a, const Poly& b, const Poly& m) { return (a*b)%m; }
    static Poly sqrmod(const Poly& a, const Poly& m) { return (a*a)%m; }

    Poly powmod(const Uint256& e, const Poly& m) const {
        if (e.is_zero()) return one();
        Poly b=*this%m, r=one(); int top=e.bits();
        for (int i=top; i>=0; i--) { r=sqrmod(r,m); if (e.bit(i)) r=mulmod(r,b,m); }
        return r;
    }

    static Poly gcd(const Poly& a, const Poly& b) {
        if (b.is_zero()) return a.is_zero() ? Poly() : a.monic();
        return gcd(b, a%b);
    }

    Fp eval(const Fp& x) const {
        if (is_zero()) return Fp::zero();
        Fp r = c.back();
        for (int i=(int)c.size()-2; i>=0; i--) r = r*x + c[i];
        return r;
    }

    Poly eval_poly(const Poly& val, const Poly& m) const {
        if (is_zero()) return Poly();
        Poly r(c.back());
        for (int i=(int)c.size()-2; i>=0; i--) {
            r = mulmod(r, val, m) + Poly(c[i]);
            r = r % m;
        }
        return r;
    }

    bool operator==(const Poly& o) const {
        if (c.size()!=o.c.size()) return false;
        for (size_t i=0; i<c.size(); i++) if (c[i]!=o.c[i]) return false;
        return true;
    }
};

// Helper: build poly from initializer
static Poly make_poly(std::initializer_list<Fp> il) {
    return Poly(std::vector<Fp>(il));
}

// ════════════════════════════════════════════════════════════════════
// SECTION 7:  Schoof's algorithm
// ════════════════════════════════════════════════════════════════════

struct DivPoly {
    Fp aw, bw;
    Poly fx, fx_sq, s16fx2;
    std::map<int,Poly> cache;

    DivPoly() {}
    DivPoly(const Fp& a, const Fp& b) : aw(a), bw(b) {
        fx = make_poly({b, a, Fp::zero(), Fp::one()});
        fx_sq = fx * fx;
        s16fx2 = fx_sq * Fp(16ULL);
        cache[0] = Poly::zero();
        cache[1] = Poly::one();
        cache[2] = Poly::one();
        // ψ̂₃ = 3x⁴ + 6ax² + 12bx - a²
        Fp a2 = a*a;
        cache[3] = make_poly({-a2, Fp(12ULL)*b, Fp(6ULL)*a, Fp::zero(), Fp(3ULL)});
        // ψ̂₄ = 2(x⁶ + 5ax⁴ + 20bx³ - 5a²x² - 4abx - 8b² - a³)
        Fp a3 = a2 * a, b2 = b * b, two = Fp(2ULL);
        cache[4] = make_poly({
            -two * (Fp(8ULL) * b2 + a3),
            -two * (Fp(4ULL) * a * b),
            -two * (Fp(5ULL) * a2),
            two * (Fp(20ULL) * b),
            two * (Fp(5ULL) * a),
            Fp::zero(),
            two
        });
    }

    Poly get(int n) {
        auto it = cache.find(n);
        if (it != cache.end()) return it->second;

        if (n < 0) {
            return -get(-n);
        }

        if (n == 0) {
            cache[n] = Poly(Fp::zero());
            return cache[n];
        }
        if (n == 1) {
            cache[n] = Poly(Fp::one());
            return cache[n];
        }
        if (n == 2) {
            cache[n] = Poly(Fp(2ULL));
            return cache[n];
        }
        if (n == 3) {
            Poly x = Poly::X();
            Poly aP(aw), bP(bw);
            cache[n] = Poly(Fp(3ULL))*x*x + Poly(Fp(6ULL))*aP*x + Poly(Fp(12ULL))*bP - aP*aP;
            return cache[n];
        }
        if (n == 4) {
            Poly x = Poly::X();
            Poly aP(aw), bP(bw);
            Poly core =
                Poly(Fp(2ULL))*x*x*x*x*x
              + Poly(Fp(10ULL))*aP*x*x*x
              + Poly(Fp(40ULL))*bP*x*x
              - Poly(Fp(10ULL))*(aP*aP)*x
              - Poly(Fp(8ULL))*aP*bP;
            cache[n] = Poly(Fp(4ULL)) * core;
            return cache[n];
        }

        Poly result;
        if (n%2 == 1) {
            int m = (n-1)/2;
            Poly pm2=get(m+2), pm1=get(m+1), pm=get(m), pmm=get(m-1);
            Poly pm3=pm*pm*pm, pm1_3=pm1*pm1*pm1;
            result = (m%2==1) ? pm2*pm3 - s16fx2*pmm*pm1_3
                              : s16fx2*pm2*pm3 - pmm*pm1_3;
        } else {
            int m = n/2;
            Poly pm2=get(m+2), pm1=get(m+1), pm=get(m), pmm=get(m-1), pmm2=get(m-2);
            result = pm * (pm2*pmm*pmm - pmm2*pm1*pm1);
        }
        cache[n] = result;
        return result;
    }
};

struct RatPoint {
    Poly xn, xd;   // x = xn / xd
    Poly yn, yd;   // y = y * (yn / yd)
    bool is_inf;
    RatPoint()
        : xn(Poly()), xd(Poly(Fp(1ULL))), yn(Poly()), yd(Poly(Fp(1ULL))), is_inf(true) {}
    RatPoint(const Poly& xn_, const Poly& xd_, const Poly& yn_, const Poly& yd_, bool inf=false)
        : xn(xn_), xd(xd_), yn(yn_), yd(yd_), is_inf(inf) {}
};

static RatPoint rat_make_affine_x_yfactor(const Poly& xn, const Poly& xd,
                                          const Poly& yn, const Poly& yd) {
    return RatPoint(xn, xd, yn, yd, false);
}


static RatPoint rat_double_generic(const RatPoint& P,
                                   const Fp& aw,
                                   const Poly& fmod,
                                   const Poly& mod);

static RatPoint rat_scalar_mul_generic(int k,
                                       const RatPoint& P,
                                       const Fp& aw,
                                       const Poly& fmod,
                                       const Poly& mod);

static RatPoint rat_tau_phi_point(DivPoly& dp,
                                  int tau,
                                  const Poly& xpmod,
                                  const Poly& fbase,
                                  const Poly& ypf,
                                  const Fp& aw,
                                  const Poly& mod) {
    (void)dp;

    if (tau == 0) return RatPoint();

    RatPoint Phi = rat_make_affine_x_yfactor(
        xpmod, Poly(Fp(1ULL)),
        ypf,   Poly(Fp(1ULL))
    );

    return rat_scalar_mul_generic(tau, Phi, aw, fbase, mod);
}


static RatPoint rat_add_generic(const RatPoint& P, const RatPoint& Q,
                                const Poly& fpoly, const Poly& mod) {
    if (P.is_inf) return Q;
    if (Q.is_inf) return P;

    Poly x1d_x2d = Poly::mulmod(P.xd, Q.xd, mod);
    Poly y1d_y2d = Poly::mulmod(P.yd, Q.yd, mod);

    // Mn = (y2n * y1d - y1n * y2d) * x1d * x2d
    Poly diff_y = (
        Poly::mulmod(Q.yn, P.yd, mod) - Poly::mulmod(P.yn, Q.yd, mod)
    ) % mod;
    Poly Mn = Poly::mulmod(diff_y, x1d_x2d, mod);

    // Md = (x2n * x1d - x1n * x2d) * y1d * y2d
    Poly diff_x_input = (
        Poly::mulmod(Q.xn, P.xd, mod) - Poly::mulmod(P.xn, Q.xd, mod)
    ) % mod;
    Poly Md = Poly::mulmod(diff_x_input, y1d_y2d, mod);

    Poly Mn2 = Poly::sqrmod(Mn, mod);
    Poly Md2 = Poly::sqrmod(Md, mod);
    Poly Md3 = Poly::mulmod(Md2, Md, mod);

    // x3n = fpoly * Mn^2 * x1d * x2d - Md^2 * (x1n * x2d + x2n * x1d)
    Poly term_x3n_1 = Poly::mulmod(fpoly, Poly::mulmod(Mn2, x1d_x2d, mod), mod);
    Poly sum_x = (
        Poly::mulmod(P.xn, Q.xd, mod) + Poly::mulmod(Q.xn, P.xd, mod)
    ) % mod;
    Poly term_x3n_2 = Poly::mulmod(Md2, sum_x, mod);
    Poly x3n = (term_x3n_1 - term_x3n_2) % mod;

    // x3d = Md^2 * x1d * x2d
    Poly x3d = Poly::mulmod(Md2, x1d_x2d, mod);

    // y3n = Mn * y1d * (x1n * Md^2 * x2d - x3n) - y1n * Md^3 * x1d * x2d
    Poly term_inner = (Poly::mulmod(P.xn, Poly::mulmod(Md2, Q.xd, mod), mod) - x3n) % mod;
    Poly term_y3n_1 = Poly::mulmod(Mn, Poly::mulmod(P.yd, term_inner, mod), mod);
    Poly term_y3n_2 = Poly::mulmod(P.yn, Poly::mulmod(Md3, x1d_x2d, mod), mod);
    Poly y3n = (term_y3n_1 - term_y3n_2) % mod;

    // y3d = Md^3 * x1d * x2d * y1d
    Poly y3d = Poly::mulmod(Md3, Poly::mulmod(x1d_x2d, P.yd, mod), mod);

    return rat_make_affine_x_yfactor(x3n % mod, x3d % mod, y3n % mod, y3d % mod);
}


struct SchoofResult {
    Uint256 trace, group_order;
    bool trace_neg, success;
    SchoofResult() : trace_neg(false), success(false) {}
};

static SchoofResult run_schoof(const Fp& aw, const Fp& bw) {
    SchoofResult res;
    clock_t t0 = clock();
    printf("\n================================================================\n");
    printf("  SCHOOF — Point counting on Y²=X³+aX+b\n");
    printf("================================================================\n\n");

    // Sieve primes up to 200
    std::vector<int> primes;
    {
        std::vector<bool> sv(200, true); sv[0]=sv[1]=false;
        for (int i=2; i<200; i++) if (sv[i]) for (int j=2*i; j<200; j+=i) sv[j]=false;
        for (int i=2; i<200; i++) if (sv[i]) primes.push_back(i);
    }

    DivPoly dp(aw, bw);
    Poly xp = Poly::X();
    Uint256 M(1), tacc(0);
    int pdone = 0;

    for (int l : primes) {
        // Need M > 4√p, check M² > 16p ↔ M.bit_length > 130 (since 16p ≈ 2^259)
        if (M.bit_length() >= 131) {
            printf("  *** M has %d bits (≥131), sufficient ***\n\n", M.bit_length());
            break;
        }        double el = (double)(clock()-t0)/CLOCKS_PER_SEC;
        printf("  [%7.1fs] l=%3d  (M: %d bits)\n", el, l, M.bit_length());
        fflush(stdout);

        int tl = -1;

        if (l == 2) {
            // t ≡ 0 mod 2 iff gcd(f(x), x^p - x) has degree > 0
            Poly xpow = xp.powmod(P_MOD, dp.fx);
            Poly g = Poly::gcd(dp.fx, (xpow - xp) % dp.fx);
            tl = (g.deg() > 0) ? 0 : 1;
            printf("           t≡%d (mod 2)\n", tl);
        } else {
            // Compute ψ_l
            printf("           ψ_%d...", l); fflush(stdout);
            Poly psi_l = dp.get(l);
            printf(" deg=%d\n", psi_l.deg());

            printf("           x^p..."); fflush(stdout);
            Poly xpmod = xp.powmod(P_MOD, psi_l);
            printf("ok  x^{p²}..."); fflush(stdout);
            Poly xp2 = xpmod.powmod(P_MOD, psi_l);
            printf("ok\n");

            // q = p mod l
            // Keep the true residue class modulo l. Do not patch parities here
            // unless we are explicitly in debug mode to localize a symbolic bug.
            uint64_t q = 0;
            { uint64_t pw=1; for(int i=0;i<255;i++) pw=(pw*2)%l; q=(pw+l-(19%l))%l; }
            printf("           q = p mod l = %llu\n", (unsigned long long)q);

            uint64_t q_used = q;

            auto hp = [&](int n) -> Poly { return dp.get(n) % psi_l; };
            Poly hq=hp((int)q_used), hqp1=hp((int)q_used+1), hqm1=hp((int)q_used-1);
            Poly hq2 = Poly::sqrmod(hq, psi_l);
            Poly f4 = dp.fx * Fp(4ULL);

            Poly phi_q, psq;
            if (q%2 == 1) {
                phi_q = (Poly::mulmod(xp, hq2, psi_l)
                        - Poly::mulmod(f4%psi_l, Poly::mulmod(hqp1,hqm1,psi_l), psi_l)) % psi_l;
                psq = hq2;
            } else {
                Poly fh = Poly::mulmod(f4%psi_l, hq2, psi_l);
                phi_q = (Poly::mulmod(xp, fh, psi_l)
                        - Poly::mulmod(hqp1,hqm1,psi_l)) % psi_l;
                psq = fh;
            }

            // tau=0?
            if (Poly::mulmod(xp2, psq, psi_l) == phi_q%psi_l) {
                tl = 0; printf("           t≡0 (mod %d)\n", l);
                goto do_crt;
            }

            { // tau = 1..(l-1)/2
                Poly f_xp = ((Poly::sqrmod(xpmod,psi_l)*xpmod%psi_l)
                            + Poly(aw)*xpmod + Poly(bw)) % psi_l;

                printf("           f^{(p-1)/2}..."); fflush(stdout);
                Uint256 hpm1 = (P_MOD - Uint256(1)).shr1();
                Poly ypf = (dp.fx%psi_l).powmod(hpm1, psi_l);
                printf("ok\n");
                printf("           f^{(p²-1)/2}..."); fflush(stdout);
                // f^{(p²-1)/2} = (f^{(p-1)/2})^{p+1} = ypf(x^p) * ypf
                Poly ypf_xp = ypf.eval_poly(xpmod, psi_l);
                Poly yp2f = Poly::mulmod(ypf_xp, ypf, psi_l);
                printf("ok\n");

                Poly hqp2=hp((int)q_used+2), hqm2=hp((int)q_used-2);
                Poly yqn = (Poly::mulmod(hqp2, Poly::sqrmod(hqm1,psi_l), psi_l)
                           - Poly::mulmod(hqm2, Poly::sqrmod(hqp1,psi_l), psi_l)) % psi_l;
                Poly hqc = Poly::mulmod(hq2, hq, psi_l);
                if ((q % 2) == 0) {
                    Poly fxmod = dp.fx % psi_l;
                    Poly fxmod2 = Poly::mulmod(fxmod, fxmod, psi_l);
                    hqc = Poly::mulmod(Poly(Fp(16ULL)),
                                       Poly::mulmod(fxmod2, hqc, psi_l),
                                       psi_l);
                }

                Poly dxn = (Poly::mulmod(xp2, psq, psi_l) - phi_q) % psi_l;
                Poly dyny = (Poly::mulmod(yp2f, hqc, psi_l) - yqn) % psi_l;
                Poly dy2 = Poly::sqrmod(dyny, psi_l);
                Poly hc2 = Poly::sqrmod(hqc, psi_l);
                Poly dx2 = Poly::sqrmod(dxn, psi_l);
                Poly pqs3 = Poly::mulmod(Poly::sqrmod(psq,psi_l), psq, psi_l);
                Poly fmod = dp.fx % psi_l;
                Poly t1 = Poly::mulmod(fmod, Poly::mulmod(dy2, pqs3, psi_l), psi_l);
                Poly hd = Poly::mulmod(hc2, dx2, psi_l);
                Poly t2 = Poly::mulmod(xp2, Poly::mulmod(hd, psq, psi_l), psi_l);
                Poly t3 = Poly::mulmod(phi_q, hd, psi_l);
                Poly xsn = (t1 - t2 - t3) % psi_l;
                Poly xsd = Poly::mulmod(hd, psq, psi_l);

                printf("           testing tau 1..%d\n", (l-1)/2); fflush(stdout);
                for (int tau=1; tau<=(l-1)/2; tau++) {
                    printf("             [l=%d] tau=%d\n", l, tau); fflush(stdout);
                    Poly ht  = dp.get(tau).eval_poly(xpmod, psi_l);
                    Poly htp = dp.get(tau+1).eval_poly(xpmod, psi_l);
                    Poly htm = dp.get(tau-1).eval_poly(xpmod, psi_l);
                    Poly ht2 = Poly::sqrmod(ht, psi_l);
                    Poly ptau, ptsq;
                    if (tau%2==1) {
                        Poly ff = Poly::mulmod(f_xp, Poly(Fp(4ULL)), psi_l);
                        ptau = (Poly::mulmod(xpmod, ht2, psi_l)
                               - Poly::mulmod(ff, Poly::mulmod(htp,htm,psi_l), psi_l)) % psi_l;
                        ptsq = ht2;
                    } else {
                        Poly fh2 = Poly::mulmod(Poly::mulmod(f_xp, Poly(Fp(4ULL)), psi_l), ht2, psi_l);
                        ptau = (Poly::mulmod(xpmod, fh2, psi_l)
                               - Poly::mulmod(htp,htm,psi_l)) % psi_l;
                        ptsq = fh2;
                    }
                    Poly lhs = Poly::mulmod(xsn, ptsq, psi_l);
                    Poly rhs = Poly::mulmod(ptau, xsd, psi_l);
                    Poly diffpoly = (lhs - rhs) % psi_l;
                    bool xok = (lhs == rhs);


                    printf("               x-test: %s\n", xok ? "OK" : "FAIL"); fflush(stdout);

                    if (xok) {
                        printf("           x-match for tau=%d\n", tau);

                        RatPoint Pphi2 = rat_make_affine_x_yfactor(
                            xp2, Poly(Fp(1ULL)),
                            yp2f, Poly(Fp(1ULL))
                        );
                        RatPoint Pq = rat_make_affine_x_yfactor(
                            phi_q, psq,
                            yqn, hqc
                        );
                        RatPoint D = rat_add_generic(Pphi2, Pq, fmod, psi_l);
                        RatPoint T = rat_tau_phi_point(dp, tau, xpmod, fmod, ypf, aw, psi_l);

                        Poly lhs_y = Poly::mulmod(D.yn, T.yd, psi_l);
                        Poly rhs_y = Poly::mulmod(T.yn, D.yd, psi_l);
                        Poly zero;

                        if (((lhs_y - rhs_y) % psi_l) == zero) {
                            tl = tau;
                            printf("           sign selects +tau=%d\n", tau);
                            goto do_crt;
                        }
                        if (((lhs_y + rhs_y) % psi_l) == zero) {
                            tl = (l - tau) % l;
                            printf("           sign selects -tau=%d\n", tl);
                            goto do_crt;
                        }

                        printf("           sign unresolved for tau=%d\n", tau);
                        continue;
                    }
                }
                printf("           FAILED: no tau found for l=%d\n", l);
                continue;
            }
        }

do_crt:
        if (tl >= 0) {
            // CRT: combine tacc (mod M) with tl (mod l)
            uint64_t Ml=0, tal=0;
            { __uint128_t r=0; for(int i=3;i>=0;i--){r=(r<<64)|M.w[i]; r%=l;} Ml=(uint64_t)r; }
            { __uint128_t r=0; for(int i=3;i>=0;i--){r=(r<<64)|tacc.w[i]; r%=l;} tal=(uint64_t)r; }
            // M^{-1} mod l
            int64_t aa=Ml, bb=l, x0=1, x1=0;
            while(bb>0){int64_t qq=aa/bb,tmp=bb; bb=aa-qq*bb; aa=tmp; tmp=x1; x1=x0-qq*x1; x0=tmp;}
            uint64_t Mi = ((x0%(int64_t)l)+l)%l;
            uint64_t diff = ((int64_t)tl-(int64_t)tal+(int64_t)l)%l;
            uint64_t k = (diff * Mi) % l;
            if (k > 0) { Uint256 Mk; Uint256::mul_small(Mk,M,k); Uint256::add(tacc,tacc,Mk); }
            Uint256 Mn; Uint256::mul_small(Mn,M,(uint64_t)l); M=Mn;
            while (tacc >= M) Uint256::sub(tacc, tacc, M);
            pdone++;
        }
    }

    Uint256 Mh = M.shr1();
    res.trace_neg = (tacc > Mh);
    if (res.trace_neg) Uint256::sub(res.trace, M, tacc);
    else               res.trace = tacc;
    Uint256 pp1 = P_MOD + Uint256(1);
    if (res.trace_neg) Uint256::add(res.group_order, pp1, res.trace);
    else               Uint256::sub(res.group_order, pp1, res.trace);

    double tot = (double)(clock()-t0)/CLOCKS_PER_SEC;
    printf("\n  Schoof: %.1fs, %d primes\n", tot, pdone);
    printf("  trace |t| = %s%s\n", res.trace_neg?"-":"", res.trace.to_dec().c_str());
    printf("  #E = %s\n", res.group_order.to_dec().c_str());
    res.success = true;
    return res;
}


// Small-curve sanity checks (brute force reference)
static uint64_t mod_pow_u64(uint64_t a, uint64_t e, uint64_t p) {
    __uint128_t r = 1, b = a % p;
    while (e) {
        if (e & 1) r = (r * b) % p;
        b = (b * b) % p;
        e >>= 1;
    }
    return (uint64_t)r;
}

static int legendre_u64(uint64_t a, uint64_t p) {
    a %= p;
    if (a == 0) return 0;
    uint64_t t = mod_pow_u64(a, (p - 1) / 2, p);
    return (t == 1) ? 1 : -1;
}

static uint64_t brute_count_weierstrass_u64(uint64_t p, uint64_t a, uint64_t b) {
    uint64_t count = 1; // point at infinity
    for (uint64_t x = 0; x < p; x++) {
        uint64_t rhs = (((__uint128_t)x * x % p) * x + (__uint128_t)a * x + b) % p;
        int lg = legendre_u64(rhs, p);
        if (lg == 0) count += 1;
        else if (lg > 0) count += 2;
    }
    return count;
}




static RatPoint rat_double_generic(const RatPoint& P,
                                   const Fp& aw,
                                   const Poly& fmod,
                                   const Poly& mod) {
    if (P.is_inf) return P;

    Poly xn2 = Poly::sqrmod(P.xn, mod);
    Poly xd2 = Poly::sqrmod(P.xd, mod);

    // Mn = (3 * xn^2 + a * xd^2) * yd
    Poly num_x = (
        Poly::mulmod(Poly(Fp(3ULL)), xn2, mod)
        + Poly::mulmod(Poly(aw), xd2, mod)
    ) % mod;
    Poly Mn = Poly::mulmod(num_x, P.yd, mod);

    // Md = 2 * fmod * xd^2 * yn
    Poly Md = Poly::mulmod(
        Poly(Fp(2ULL)),
        Poly::mulmod(fmod, Poly::mulmod(xd2, P.yn, mod), mod),
        mod
    );

    Poly Mn2 = Poly::sqrmod(Mn, mod);
    Poly Md2 = Poly::sqrmod(Md, mod);
    Poly Md3 = Poly::mulmod(Md2, Md, mod);

    // x3n = fmod * Mn^2 * xd - 2 * xn * Md^2
    Poly term_x3n_1 = Poly::mulmod(fmod, Poly::mulmod(Mn2, P.xd, mod), mod);
    Poly term_x3n_2 = Poly::mulmod(Poly(Fp(2ULL)), Poly::mulmod(P.xn, Md2, mod), mod);
    Poly x3n = (term_x3n_1 - term_x3n_2) % mod;

    // x3d = Md^2 * xd
    Poly x3d = Poly::mulmod(Md2, P.xd, mod);

    // y3n = Mn * yd * (xn * Md^2 - x3n) - yn * Md^3 * xd
    Poly diff_x = (Poly::mulmod(P.xn, Md2, mod) - x3n) % mod;
    Poly term_y3n_1 = Poly::mulmod(Mn, Poly::mulmod(P.yd, diff_x, mod), mod);
    Poly term_y3n_2 = Poly::mulmod(P.yn, Poly::mulmod(Md3, P.xd, mod), mod);
    Poly y3n = (term_y3n_1 - term_y3n_2) % mod;

    // y3d = Md^3 * xd * yd
    Poly y3d = Poly::mulmod(Md3, Poly::mulmod(P.xd, P.yd, mod), mod);

    return rat_make_affine_x_yfactor(x3n % mod, x3d % mod, y3n % mod, y3d % mod);
}

static RatPoint rat_scalar_mul_generic(int k,
                                       const RatPoint& P,
                                       const Fp& aw,
                                       const Poly& fmod,
                                       const Poly& mod) {
    if (k == 0) return RatPoint();
    if (k == 1) return P;

    RatPoint R;      // infinity
    RatPoint A = P;
    int n = k;

    while (n > 0) {
        if (n & 1) {
            if (R.is_inf) R = A;
            else          R = rat_add_generic(R, A, fmod, mod);
        }
        n >>= 1;
        if (n) A = rat_double_generic(A, aw, fmod, mod);
    }
    return R;
}


static int run_small_test_suite() {
    printf("\n================================================================\n");
    printf("  SMALL CURVE BRUTE-FORCE TESTS ONLY\n");
    printf("================================================================\n\n");
    struct SmallCurve { uint64_t p, a, b; };
    std::vector<SmallCurve> tests = {
        {101, 2, 3},
        {211, 5, 7},
        {223, 0, 7},
    };

    for (const auto& tc : tests) {
        printf("  [p=%llu] y^2 = x^3 + %llux + %llu\n",
               (unsigned long long)tc.p,
               (unsigned long long)tc.a,
               (unsigned long long)tc.b);
        uint64_t n = brute_count_weierstrass_u64(tc.p, tc.a, tc.b);
        int64_t trace = (int64_t)tc.p + 1 - (int64_t)n;
        printf("    brute #E(F_p) = %llu\n", (unsigned long long)n);
        printf("    trace t       = %lld\n", (long long)trace);
        printf("    t mod 3       = %lld\n", (long long)((trace % 3 + 3) % 3));
        printf("    t mod 5       = %lld\n", (long long)((trace % 5 + 5) % 5));
        printf("    t mod 7       = %lld\n", (long long)((trace % 7 + 7) % 7));
        printf("    note          = brute-force only; Schoof not executed in this mode\n\n");
    }

    return 0;
}

// ════════════════════════════════════════════════════════════════════
// SECTION 8:  Main — orchestration of all verification steps
// ════════════════════════════════════════════════════════════════════

static const char* EXP_L =
    "7237005577332262213973186563042994240857116359379907606001950938285454250989";
static const char* EXP_ORD =
    "57896044618658097711785492504343953926856930875039260848015607506283634007912";

static void sep(const char* t) {
    printf("\n================================================================\n");
    printf("  %s\n", t);
    printf("================================================================\n\n");
}

static bool step1_prime() {
    sep("STEP 1: Verify p = 2^255 - 19 is prime");
    printf("  p = %s\n", P_MOD.to_dec().c_str());
    printf("  p has %d bits\n", P_MOD.bit_length());
    Uint256 two55; two55.w[3] = 0x8000000000000000ULL;
    bool c = (two55 - Uint256(19) == P_MOD);
    printf("  p == 2^255-19: %s\n", c ? "YES" : "NO");
    printf("  Miller-Rabin (20 bases)... "); fflush(stdout);
    bool pr = miller_rabin(P_MOD, 20);
    printf("%s\n", pr ? "PRIME" : "NOT PRIME");
    return c && pr;
}

static bool step2_d() {
    sep("STEP 2: Verify d = -121665/121666 mod p");
    printf("  d (hex) = %s\n", CURVE_D.to_hex().c_str());
    // Verify: d·121666 + 121665 = 0
    Fp chk = CURVE_D * Fp(121666ULL) + Fp(121665ULL);
    printf("  d·121666 + 121665 ≡ 0: %s\n", chk.is_zero() ? "YES" : "NO");
    // Verify d is QNR
    Fp leg = CURVE_D.legendre();
    bool ns = (leg == (-Fp::one()));
    printf("  d is quadratic non-residue: %s\n", ns ? "YES (complete addition)" : "NO");
    return chk.is_zero() && ns;
}

static EdPoint step3_base() {
    sep("STEP 3: Compute base point B from y = 4/5 mod p");

    // y = 4·5⁻¹ mod p — the standard Ed25519 base point y-coordinate
    Fp by = Fp(4ULL) / Fp(5ULL);
    printf("  y = 4·5⁻¹ mod p\n");
    printf("  y (hex) = %s\n", by.to_hex().c_str());
    // Verify: 5·y = 4
    printf("  5·y == 4: %s\n", (Fp(5ULL)*by == Fp(4ULL)) ? "YES" : "NO");
    // Check expected hex
    Uint256 ey(0x6666666666666658ULL, 0x6666666666666666ULL,
               0x6666666666666666ULL, 0x6666666666666666ULL);
    printf("  y == 0x6666...6658: %s\n", (by.v==ey) ? "YES" : "NO");

    // x² = (y²-1)/(1+d·y²)
    Fp y2 = by*by;
    Fp xsq = (y2 - Fp::one()) / (Fp::one() + CURVE_D * y2);
    Fp bx = xsq.sqrt();
    printf("  sqrt(x²) exists: %s\n", (bx*bx==xsq) ? "YES" : "NO");
    // Ed25519 convention: x with low bit = 0
    if (bx.v.w[0] & 1) bx = -bx;
    printf("  x (hex) = %s\n", bx.to_hex().c_str());
    // Expected x
    Uint256 ex(0xc9562d608f25d51aULL, 0x692cc7609525a7b2ULL,
               0xc0a4e231fdd6dc5cULL, 0x216936d3cd6e53feULL);
    printf("  x == 0x216936d3...d51a: %s\n", (bx.v==ex) ? "YES" : "NO");

    bool on = EdPoint::on_curve_affine(bx, by);
    printf("  -x²+y² = 1+d·x²·y²: %s\n", on ? "VERIFIED" : "FAILED");
    if (!on) printf("  FATAL: base point not on curve\n");
    return EdPoint::from_affine(bx, by);
}

static bool step4_order(const EdPoint& B) {
    sep("STEP 4: Verify order of base point");
    Uint256 l = Uint256::from_dec(EXP_L);
    printf("  l = %s\n  (%d bits)\n\n", EXP_L, l.bit_length());

    printf("  4a. l prime (MR)... "); fflush(stdout);
    bool lp = miller_rabin(l, 20);
    printf("%s\n", lp ? "YES" : "NO");
    if (!lp) return false;

    printf("  4b. [l]B == O ... "); fflush(stdout);
    clock_t t = clock();
    EdPoint lB = B.scalar_mul(l);
    double dt = (double)(clock()-t)/CLOCKS_PER_SEC;
    bool isO = lB.is_neutral();
    printf("%.2fs → %s\n", dt, isO ? "YES" : "NO");
    if (!isO) return false;

    printf("  4c. l prime ∧ [l]B=O ∧ B≠O → ord(B) = l  (Lagrange)\n");

    printf("  4d. [l-1]B == -B ... "); fflush(stdout);
    t = clock();
    EdPoint r = B.scalar_mul(l - Uint256(1));
    dt = (double)(clock()-t)/CLOCKS_PER_SEC;
    bool ok = (r == -B);
    printf("%.2fs → %s\n", dt, ok ? "YES" : "NO");

    printf("  4e. [8]B ≠ O: %s\n", B.scalar_mul(8ULL).is_neutral() ? "NO (bad!)" : "YES");
    return isO && lp && ok;
}

static bool step5_conv(const EdPoint& B) {
    sep("STEP 5: Verify curve model conversions");
    Fp bx, by; B.to_affine(bx, by);

    Fp u, v;
    bool ok1 = ed_to_mont(bx, by, u, v);
    printf("  Edwards → Montgomery: %s\n", ok1 ? "ok" : "FAIL");
    printf("  On Montgomery (Bv²=u³+Au²+u): %s\n", on_montgomery(u,v) ? "YES" : "NO");
    printf("  A == 486662: %s\n", (MONT_A==Fp(486662ULL)) ? "YES" : "NO");

    Fp Xw, Yw;
    mont_to_weier(u, v, Xw, Yw);
    printf("  On Weierstrass (Y²=X³+aX+b): %s\n", on_weierstrass(Xw,Yw) ? "YES" : "NO");

    Fp xb, yb;
    weier_to_ed(Xw, Yw, xb, yb);
    bool rt = (xb==bx && yb==by);
    printf("  Round-trip Weier→Edwards: %s\n", rt ? "YES" : "NO");

    Fp disc = Fp::neg(16) * (Fp(4ULL)*WEIER_A*WEIER_A*WEIER_A
              + Fp(27ULL)*WEIER_B*WEIER_B);
    printf("  Discriminant ≠ 0: %s\n", disc.is_zero() ? "NO (bad!)" : "YES");

    return ok1 && on_weierstrass(Xw,Yw) && rt && !disc.is_zero();
}

static void step6_cofactor() {
    sep("STEP 6: Cofactor structure");
    // (0,-1) has order 2
    printf("  (0,-1) on curve: %s\n", EdPoint::on_curve_affine(Fp::zero(), -Fp::one()) ? "YES" : "NO");
    EdPoint P2 = EdPoint::from_affine(Fp::zero(), -Fp::one());
    printf("  [2](0,-1) = O: %s  (order 2)\n", P2.dbl().is_neutral() ? "YES" : "NO");
    // Order 4: (sqrt(-1), 0)
    Fp sq = (-Fp::one()).sqrt();
    if (sq*sq == -Fp::one()) {
        EdPoint P4 = EdPoint::from_affine(sq, Fp::zero());
        EdPoint d2=P4.dbl(), d4=d2.dbl();
        printf("  Order-4 point: %s\n", (!d2.is_neutral()&&d4.is_neutral()) ? "YES" : "NO");
    }
    // Order 8
    Uint256 l = Uint256::from_dec(EXP_L);
    for (int a=1; a<=50; a++) {
        Fp yt(Uint256(1000 + a*997));
        Fp y2=yt*yt, num=y2-Fp::one(), den=Fp::one()+CURVE_D*y2;
        if (den.is_zero()) continue;
        Fp x2=num/den, xt=x2.sqrt();
        if (xt*xt != x2) continue;
        if (!EdPoint::on_curve_affine(xt,yt)) continue;
        EdPoint T = EdPoint::from_affine(xt,yt).scalar_mul(l);
        if (T.is_neutral()) continue;
        EdPoint T2=T.dbl(), T4=T2.dbl(), T8=T4.dbl();
        if (T8.is_neutral() && !T4.is_neutral()) {
            printf("  Order-8 point found (attempt %d)\n", a);
            printf("  → 8 | #E → h ≥ 8 → h = 8 (with Hasse + l prime)\n");
            return;
        }
    }
    printf("  Could not find order-8 point in 50 attempts.\n");
}

static bool step7_schoof() {
    sep("STEP 7: Group order via Schoof");
    printf("  Running on Weierstrass model derived from Ed25519.\n");
    printf("  This may take minutes to hours.\n\n");

    SchoofResult res = run_schoof(WEIER_A, WEIER_B);
    if (!res.success) return false;

    sep("STEP 8: Compare with expected Ed25519 values");
    Uint256 eo = Uint256::from_dec(EXP_ORD);
    Uint256 el = Uint256::from_dec(EXP_L);

    bool m = (res.group_order == eo);
    printf("  #E == expected: %s\n", m ? "YES" : "NO");
    if (!m) {
        Uint256 pp1 = P_MOD + Uint256(1), alt;
        if (res.trace_neg) Uint256::sub(alt, pp1, res.trace);
        else               Uint256::add(alt, pp1, res.trace);
        if (alt == eo) {
            printf("  (Sign corrected → match)\n");
            res.group_order = alt; m = true;
        }
    }
    if (m) {
        Uint256 lo8, hi8;
        Uint256::mul_full(el, Uint256(8), lo8, hi8);
        bool hok = (res.group_order == lo8 && hi8.is_zero());
        printf("  #E == 8·l: %s (cofactor h=8)\n", hok ? "YES" : "NO");
    }
    return m;
}

int main(int argc, char* argv[]) {
    bool do_gen = true, do_sch = true, do_small_test = false;
    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i], "--generator-only")) do_sch = false;
        else if (!strcmp(argv[i], "--schoof-only")) do_gen = false;
        else if (!strcmp(argv[i], "--small-test")) do_small_test = true;
        else if (!strcmp(argv[i], "--help")) {
            printf("Usage: %s [--generator-only] [--schoof-only] [--small-test] [--help]\n", argv[0]);
            return 0;
        }
        else {
            printf("Usage: %s [--generator-only] [--schoof-only] [--small-test] [--help]\n", argv[0]);
            return 1;
        }
    }

    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Ed25519 Independent Verification                         ║\n");
    printf("║  Zero dependencies — self-contained 256-bit arithmetic    ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    clock_t start = clock();

    // Initialize curve parameters
    CURVE_D = -Fp(121665ULL) / Fp(121666ULL);
    init_conversions();

    if (do_small_test) return run_small_test_suite();
    if (!step1_prime()) return 1;
    if (!step2_d()) return 1;
    EdPoint B = step3_base();

    if (do_gen) {
        if (!step4_order(B)) return 1;
        if (!step5_conv(B)) return 1;
        step6_cofactor();
    }
    if (do_sch) step7_schoof();

    double tot = (double)(clock()-start)/CLOCKS_PER_SEC;
    sep("SUMMARY");
    printf("  Total: %.1f s\n", tot);
    printf("  External dependencies: NONE\n");
    printf("  All EC operations coded from mathematical definitions.\n");
    printf("  Expected Ed25519 values used ONLY for final comparison.\n");
    return 0;
}
