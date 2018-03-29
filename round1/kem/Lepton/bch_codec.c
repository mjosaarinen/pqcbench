/* This file is based on the public domain implementation in
 * https://github.com/mborgerding/bch_codec
 * Ivan Djelic <ivan.djelic@parrot.com> and Mark Borgerding (mark@borgerding.net).
 * The program is modified to deal with bch codes with 5<=m<=9
 */
 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bch_codec.h"

static inline int FLS(uint32_t x)
{
    int r=0;
    if (x>=(1<<16)) { r+=16;x>>=16; }
    if (x>=(1<< 8)) { r+= 8;x>>= 8; }
    if (x>=(1<< 4)) { r+= 4;x>>= 4; }
    if (x>=(1<< 2)) { r+= 2;x>>= 2; }
    if (x>=(1<< 1)) { r+= 1;x>>= 1; }
    return r+x;
}

#define GF_M(_p)               ((_p)->m)
#define GF_T(_p)               ((_p)->t)
#define GF_N(_p)               ((_p)->n)
#define GF_B(_p)               ((_p)->ecc_bits)

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

#define BCH_ECC_BYTES(_p)      DIV_ROUND_UP(GF_B(_p), 8)

/*
 * represent a polynomial over GF(2^m)
 */
struct gf_poly {
    uint16_t deg;    /* polynomial degree */
    uint16_t c[0];   /* polynomial terms */
};

/* given its degree, compute a polynomial size in bytes */
#define GF_POLY_SZ(_d) (sizeof(struct gf_poly)+((_d)+1)*sizeof(uint16_t))

/* polynomial of degree 1 */
struct gf_poly_deg1 {
    struct gf_poly poly;
    uint16_t   c[2];
};

static inline uint16_t modulo(struct bch_control *bch, unsigned int v)
{
    const unsigned int n = GF_N(bch);
    while (v >= n) {
        v -= n;
        v = (v & n) + (v >> GF_M(bch));
    }
    return v;
}

/*
 * shorter and faster modulo function, only works when v < 2N.
 */
static inline uint16_t mod_s(struct bch_control *bch, unsigned int v)
{
    const unsigned int n = GF_N(bch);
    return (v < n) ? v : v-n;
}

static inline int deg(uint32_t poly)
{
    /* polynomial degree is the most-significant bit index */
    return FLS(poly)-1;
}

static const int ParityTable256[256] =
{
#   define P2(n) n, n^1, n^1, n
#   define P4(n) P2(n), P2(n^1), P2(n^1), P2(n)
#   define P6(n) P4(n), P4(n^1), P4(n^1), P4(n)
    P6(0), P6(1), P6(1), P6(0)
};

static inline int parity(uint16_t x)
{
    /*
     * public domain code snippet, from
     * http://www-graphics.stanford.edu/~seander/bithacks.html
     */
    uint8_t * p = (uint8_t *) &x;
    return ParityTable256[p[0]^p[1]];
}

/* Galois field basic operations: multiply, divide, inverse, etc. */

static inline uint16_t gf_mul(struct bch_control *bch, unsigned int a,
                              unsigned int b)
{
    return (a && b) ? bch->a_pow_tab[mod_s(bch, bch->a_log_tab[a]+
                                           bch->a_log_tab[b])] : 0;
}

static inline uint16_t gf_sqr(struct bch_control *bch, unsigned int a)
{
    return a ? bch->a_pow_tab[mod_s(bch, 2*bch->a_log_tab[a])] : 0;
}

static inline uint16_t gf_div(struct bch_control *bch, unsigned int a,
                              unsigned int b)
{
    return a ? bch->a_pow_tab[mod_s(bch, bch->a_log_tab[a]+
                                    GF_N(bch)-bch->a_log_tab[b])] : 0;
}

static inline uint16_t gf_inv(struct bch_control *bch, unsigned int a)
{
    return bch->a_pow_tab[GF_N(bch)-bch->a_log_tab[a]];
}

static inline uint16_t a_pow(struct bch_control *bch, int i)
{
    return bch->a_pow_tab[modulo(bch, i)];
}

static inline uint16_t a_log(struct bch_control *bch, unsigned int x)
{
    return bch->a_log_tab[x];
}

static inline uint16_t a_ilog(struct bch_control *bch, unsigned int x)
{
    return mod_s(bch, GF_N(bch)-bch->a_log_tab[x]);
}

static void compute_syndromes(struct bch_control *bch, uint8_t *ecc,
                              uint16_t *syn)
{
    int i, j, s;
    unsigned int m;
    uint8_t poly;
    const int t = GF_T(bch);
    
    s = bch->ecc_bits;
    
    /* make sure extra bits in last ecc word are cleared */
    m = ((unsigned int)s) & 7;
    if (m)
        ecc[s/8] &= ~((1 << (7-m))-1);
    memset(syn, 0, 2*t*sizeof(*syn));
    
    /* compute v(a^j) for j=1 .. 2t-1 */
    
    int k1=0,nz=0;
    uint16_t locator[CACHE_SIZE]={0},dlocator[CACHE_SIZE]={0},tsyn;//size < 2t+1
    do {
        poly = *ecc++;
        s -= 8;
        while (poly) {
            i = deg(poly);
            k1 = s+i;
            locator[nz] = k1;
            dlocator[nz++] = mod_s(bch,k1<<1);
            poly ^= (1 << i);
        }
    } while (s > 0);
    
    for (j = 0;j < 2*t;j += 2)
    {
        tsyn=0;
        for(i=0;i<nz;i++)
        {
            k1 = locator[i];
            locator[i]=mod_s(bch,k1+dlocator[i]);
            tsyn ^= bch->a_pow_tab[k1];
            
        }
        syn[j] = tsyn;
    }
    for (j = 0; j < t; j++)
        syn[2*j+1] = gf_sqr(bch, syn[j]);
}


static void gf_poly_copy(struct gf_poly *dst, struct gf_poly *src)
{
    memcpy(dst, src, GF_POLY_SZ(src->deg));
}

static int compute_error_locator_polynomial(struct bch_control *bch, struct gf_poly *elp, const uint16_t *syn)
{
    const unsigned int t = GF_T(bch);
    const unsigned int n = GF_N(bch);
    uint16_t i, j, tmp, l, pd = 1, d = syn[0];
    
    
    uint8_t tpoly_2t[4][CACHE_SIZE];
    struct gf_poly *pelp = (struct gf_poly *)tpoly_2t[0];
    struct gf_poly *elp_copy = (struct gf_poly *)tpoly_2t[1];
    
    int k, pp = -1;
      
    memset(pelp, 0, GF_POLY_SZ(2*t));
    memset(elp, 0, GF_POLY_SZ(2*t));
    
    pelp->deg = 0;
    pelp->c[0] = 1;
    elp->deg = 0;
    elp->c[0] = 1;
    
    /* use simplified binary Berlekamp-Massey algorithm */
    for (i = 0; (i < t) && (elp->deg <= t); i++) {
        if (d) {
            k = 2*i-pp;
            gf_poly_copy(elp_copy, elp);
            /* e[i+1](X) = e[i](X)+di*dp^-1*X^2(i-p)*e[p](X) */
            tmp = a_log(bch, d)+n-a_log(bch, pd);
            tmp = mod_s(bch,tmp);
            for (j = 0; j <= pelp->deg; j++)
            {
                if (pelp->c[j])
                {
                    l = mod_s(bch,tmp+a_log(bch, pelp->c[j]));
                    elp->c[j+k] ^= bch->a_pow_tab[l];
                }
            }
            /* compute l[i+1] = max(l[i]->c[l[p]+2*(i-p]) */
            tmp = pelp->deg+k;
            if (tmp > elp->deg) {
                elp->deg = tmp;
                gf_poly_copy(pelp, elp_copy);
                pd = d;
                pp = 2*i;
            }
        }
        /* di+1 = S(2i+3)+elp[i+1].1*S(2i+2)+...+elp[i+1].lS(2i+3-l) */
        if (i < t-1) {
            d = syn[2*i+2];
            for (j = 1; j <= elp->deg; j++)
                d ^= gf_mul(bch, elp->c[j], syn[2*i+2-j]);
        }
    }
    return (elp->deg > t) ? -1 : (int)elp->deg;
}

/*
 * solve a m x m linear system in GF(2) with an expected number of solutions,
 * and return the number of found solutions
 */
static int solve_linear_system(struct bch_control *bch, uint16_t *rows,
                               uint16_t *sol, int nsol)
{
    const int m = GF_M(bch);
    uint16_t tmp, mask;
    int16_t rem, c, r, p, k, param[m];
    
    k = 0;
    mask = 1 << m;
    
    /* Gaussian elimination */
    for (c = 0; c < m; c++) {
        rem = 0;
        p = c-k;
        /* find suitable row for elimination */
        for (r = p; r < m; r++) {
            if (rows[r] & mask) {
                if (r != p) {
                    tmp = rows[r];
                    rows[r] = rows[p];
                    rows[p] = tmp;
                }
                rem = r+1;
                break;
            }
        }
        if (rem) {
            /* perform elimination on remaining rows */
            tmp = rows[p];
            for (r = rem; r < m; r++) {
                if (rows[r] & mask)
                    rows[r] ^= tmp;
            }
        } else {
            /* elimination not needed, store defective row index */
            param[k++] = c;
        }
        mask >>= 1;
    }
    /* rewrite system, inserting fake parameter rows */
    if (k > 0) {
        p = k;
        for (r = m-1; r >= 0; r--) {
            if ((r > m-1-k) && rows[r])
            /* system has no solution */
                return 0;
            
            rows[r] = (p && (r == param[p-1])) ?
            p--, 1u << (m-r) : rows[r-p];
        }
    }
    
    if (nsol != (1 << k))
    /* unexpected number of solutions */
        return 0;
    
    for (p = 0; p < nsol; p++) {
        /* set parameters for p-th solution */
        for (c = 0; c < k; c++)
            rows[param[c]] = (rows[param[c]] & ~1)|((p >> c) & 1);
        
        /* compute unique solution */
        tmp = 0;
        for (r = m-1; r >= 0; r--) {
            mask = rows[r] & (tmp|1);
            tmp |= parity(mask) << (m-r);
        }
        sol[p] = tmp >> 1;
    }
    return nsol;
}

/*
 * this function builds and solves a linear system for finding roots of a degree
 * 4 affine monic polynomial X^4+aX^2+bX+c over GF(2^m).
 */
static int find_affine4_roots(struct bch_control *bch, uint16_t a,
                              uint16_t b, uint16_t c,
                              uint16_t *roots)
{
    int i, j, k;
    const int m = GF_M(bch);
    uint16_t mask = 0xff, t, rows[16] = {0,};
    
    j = a_log(bch, b);
    k = a_log(bch, a);
    rows[0] = c;
    
    /* buid linear system to solve X^4+aX^2+bX+c = 0 */
    for (i = 0; i < m; i++) {
        rows[i+1] = bch->a_pow_tab[4*i]^
        (a ? bch->a_pow_tab[mod_s(bch, k)] : 0)^
        (b ? bch->a_pow_tab[mod_s(bch, j)] : 0);
        j++;
        k += 2;
    }
    /*
     * transpose 16x16 matrix before passing it to linear solver
     * warning: this code assumes m < 16
     */
    for (j = 8; j != 0; j >>= 1, mask ^= (mask << j)) {
        for (k = 0; k < 16; k = (k+j+1) & ~j) {
            t = ((rows[k] >> j)^rows[k+j]) & mask;
            rows[k] ^= (t << j);
            rows[k+j] ^= t;
        }
    }
    return solve_linear_system(bch, rows, roots, 4);
}

/*
 * compute root r of a degree 1 polynomial over GF(2^m) (returned as log(1/r))
 */
static int find_poly_deg1_roots(struct bch_control *bch, struct gf_poly *poly,
                                uint16_t *roots)
{
    int n = 0;
    
    if (poly->c[0])
    /* poly[X] = bX+c with c!=0, root=c/b */
        roots[n++] = mod_s(bch, GF_N(bch)-bch->a_log_tab[poly->c[0]]+
                           bch->a_log_tab[poly->c[1]]);
    return n;
}

/*
 * compute roots of a degree 2 polynomial over GF(2^m)
 */
static int find_poly_deg2_roots(struct bch_control *bch, struct gf_poly *poly,
                                uint16_t *roots)
{
    int n = 0, i, l0, l1, l2;
    uint16_t u, v, r;
    
    if (poly->c[0] && poly->c[1]) {
        
        l0 = bch->a_log_tab[poly->c[0]];
        l1 = bch->a_log_tab[poly->c[1]];
        l2 = bch->a_log_tab[poly->c[2]];
        
        /* using z=a/bX, transform aX^2+bX+c into z^2+z+u (u=ac/b^2) */
        u = a_pow(bch, l0+l2+2*(GF_N(bch)-l1));
        /*
         * let u = sum(li.a^i) i=0..m-1; then compute r = sum(li.xi):
         * r^2+r = sum(li.(xi^2+xi)) = sum(li.(a^i+Tr(a^i).a^k)) =
         * u + sum(li.Tr(a^i).a^k) = u+a^k.Tr(sum(li.a^i)) = u+a^k.Tr(u)
         * i.e. r and r+1 are roots iff Tr(u)=0
         */
        r = 0;
        v = u;
        while (v) {
            i = deg(v);
            r ^= bch->xi_tab[i];
            v ^= (1 << i);
        }
        /* verify root */
        if ((gf_sqr(bch, r)^r) == u) {
            /* reverse z=a/bX transformation and compute log(1/r) */
            roots[n++] = modulo(bch, 2*GF_N(bch)-l1- bch->a_log_tab[r]+l2);
            roots[n++] = modulo(bch, 2*GF_N(bch)-l1- bch->a_log_tab[r^1]+l2);
        }
    }
    return n;
}

/*
 * compute roots of a degree 3 polynomial over GF(2^m)
 */
static int find_poly_deg3_roots(struct bch_control *bch, struct gf_poly *poly,
                                uint16_t *roots)
{
    int i, n = 0;
    uint16_t a, b, c, a2, b2, c2, e3,tmp[4];
    
    if (poly->c[0]) {
        /* transform polynomial into monic X^3 + a2X^2 + b2X + c2 */
        e3 = poly->c[3];
        c2 = gf_div(bch, poly->c[0], e3);
        b2 = gf_div(bch, poly->c[1], e3);
        a2 = gf_div(bch, poly->c[2], e3);
        
        /* (X+a2)(X^3+a2X^2+b2X+c2) = X^4+aX^2+bX+c (affine) */
        c = gf_mul(bch, a2, c2);           /* c = a2c2      */
        b = gf_mul(bch, a2, b2)^c2;        /* b = a2b2 + c2 */
        a = gf_sqr(bch, a2)^b2;            /* a = a2^2 + b2 */
        
        /* find the 4 roots of this affine polynomial */
        if (find_affine4_roots(bch, a, b, c, tmp) == 4) {
            /* remove a2 from final list of roots */
            for (i = 0; i < 4; i++) {
                if (tmp[i] != a2)
                    roots[n++] = a_ilog(bch, tmp[i]);
            }
        }
    }
    return n;
}

/*
 * compute roots of a degree 4 polynomial over GF(2^m)
 */
static int find_poly_deg4_roots(struct bch_control *bch, struct gf_poly *poly,
                                uint16_t *roots)
{
    int i, l, n = 0;
    uint16_t a, b, c, d, e = 0, f, a2, b2, c2, e4;
    
    if (poly->c[0] == 0)
        return 0;
    
    /* transform polynomial into monic X^4 + aX^3 + bX^2 + cX + d */
    e4 = poly->c[4];
    d = gf_div(bch, poly->c[0], e4);
    c = gf_div(bch, poly->c[1], e4);
    b = gf_div(bch, poly->c[2], e4);
    a = gf_div(bch, poly->c[3], e4);
    
    /* use Y=1/X transformation to get an affine polynomial */
    if (a) {
        /* first, eliminate cX by using z=X+e with ae^2+c=0 */
        if (c) {
            /* compute e such that e^2 = c/a */
            f = gf_div(bch, c, a);
            l = a_log(bch, f);
            l += (l & 1) ? GF_N(bch) : 0;
            e = a_pow(bch, l/2);
            /*
             * use transformation z=X+e:
             * z^4+e^4 + a(z^3+ez^2+e^2z+e^3) + b(z^2+e^2) +cz+ce+d
             * z^4 + az^3 + (ae+b)z^2 + (ae^2+c)z+e^4+be^2+ae^3+ce+d
             * z^4 + az^3 + (ae+b)z^2 + e^4+be^2+d
             * z^4 + az^3 +     b'z^2 + d'
             */
            d = a_pow(bch, 2*l)^gf_mul(bch, b, f)^d;
            b = gf_mul(bch, a, e)^b;
        }
        /* now, use Y=1/X to get Y^4 + b/dY^2 + a/dY + 1/d */
        if (d == 0)
        /* assume all roots have multiplicity 1 */
            return 0;
        
        c2 = gf_inv(bch, d);
        b2 = gf_div(bch, a, d);
        a2 = gf_div(bch, b, d);
    } else {
        /* polynomial is already affine */
        c2 = d;
        b2 = c;
        a2 = b;
    }
    /* find the 4 roots of this affine polynomial */
    if (find_affine4_roots(bch, a2, b2, c2, roots) == 4) {
        for (i = 0; i < 4; i++) {
            /* post-process roots (reverse transformations) */
            f = a ? gf_inv(bch, roots[i]) : roots[i];
            roots[i] = a_ilog(bch, f^e);
        }
        n = 4;
    }
    return n;
}

/*
 * build monic, log-based representation of a polynomial
 */
static void gf_poly_logrep(struct bch_control *bch,
                           const struct gf_poly *a, int16_t *rep)
{
    int i, d = a->deg, l = GF_N(bch)-a_log(bch, a->c[a->deg]);
	   
    /* represent 0 values with -1; warning, rep[d] is not set to 1 */
    for (i = 0; i < d; i++)
        rep[i] = a->c[i] ? mod_s(bch, a_log(bch, a->c[i])+l) : -1;
}

/*
 * compute polynomial Euclidean division remainder in GF(2^m)[X]
 */
static void gf_poly_mod(struct bch_control *bch, struct gf_poly *a,
                        const struct gf_poly *b, int16_t *log_rep)
{
    int la, p, m;
    uint16_t i, j, *c = a->c;
    const unsigned int d = b->deg;
	   
    //  if(d>6000)
    //  	printf("d=%d\n",d);
    if (a->deg < d)
        return;
    
    int16_t *rep= log_rep;
    
    /* reuse or compute log representation of denominator */
    if (!rep) {
        int16_t cache [CACHE_SIZE];
        rep = cache;
        gf_poly_logrep(bch, b, rep);
    }
    
    for (j = a->deg; j >= d; j--) {
        if (c[j]) {
            la = a_log(bch, c[j]);
            p = j-d;
            for (i = 0; i < d; i++, p++) {
                m = rep[i];
                if (m >= 0)
                    c[p] ^= bch->a_pow_tab[mod_s(bch,
                                                 m+la)];
            }
        }
    }
    a->deg = d-1;
    while (!c[a->deg] && a->deg)
        a->deg--;
}

/*
 * compute polynomial Euclidean division quotient in GF(2^m)[X]
 */
static void gf_poly_div(struct bch_control *bch, struct gf_poly *a,
                        const struct gf_poly *b, struct gf_poly *q)
{
    if (a->deg >= b->deg) {
        q->deg = a->deg-b->deg;
        /* compute a mod b (modifies a) */
        gf_poly_mod(bch, a, b, NULL);
        /* quotient is stored in upper part of polynomial a */
        memcpy(q->c, &a->c[b->deg], (1+q->deg)*sizeof(uint16_t));
    } else {
        q->deg = 0;
        q->c[0] = 0;
    }
}

/*
 * compute polynomial GCD (Greatest Common Divisor) in GF(2^m)[X]
 */
static struct gf_poly *gf_poly_gcd(struct bch_control *bch, struct gf_poly *a,
                                   struct gf_poly *b)
{
    struct gf_poly *tmp;
    
    if (a->deg < b->deg) {
        tmp = b;
        b = a;
        a = tmp;
    }
    
    while (b->deg > 0) {
        gf_poly_mod(bch, a, b, NULL);
        tmp = b;
        b = a;
        a = tmp;
    }
    return a;
}

/*
 * Given a polynomial f and an integer k, compute Tr(a^kX) mod f
 * This is used in Berlekamp Trace algorithm for splitting polynomials
 */
static void compute_trace_bk_mod(struct bch_control *bch, int k,
                                 const struct gf_poly *f, struct gf_poly *z,
                                 struct gf_poly *out)
{
    const int m = GF_M(bch);
    int i, j;
    
    /* z contains z^2j mod f */
    z->deg = 1;
    z->c[0] = 0;
    z->c[1] = bch->a_pow_tab[k];
    
    out->deg = 0;
    memset(out, 0, GF_POLY_SZ(f->deg));
    
    /* compute f log representation only once */
    
    int16_t cache[CACHE_SIZE];//size <=
    gf_poly_logrep(bch, f, cache);
    for (i = 0; i < m; i++) {
        /* add a^(k*2^i)(z^(2^i) mod f) and compute (z^(2^i) mod f)^2 */
        for (j = z->deg; j >= 0; j--) {
            out->c[j] ^= z->c[j];
            z->c[2*j] = gf_sqr(bch, z->c[j]);
            z->c[2*j+1] = 0;
        }
        if (z->deg > out->deg)
            out->deg = z->deg;
        
        if (i < m-1) {
            z->deg *= 2;
            /* z^(2(i+1)) mod f = (z^(2^i) mod f)^2 mod f */
            gf_poly_mod(bch, z, f, cache);
        }
    }
    while (!out->c[out->deg] && out->deg)
        out->deg--;
}

/*
 * factor a polynomial using Berlekamp Trace algorithm (BTA)
 */
static void factor_polynomial(struct bch_control *bch, int k, struct gf_poly *f,struct gf_poly **g,  struct gf_poly **h)
{
    //uint8_t tpoly_2t[4][2*(bch->t+1)*sizeof(uint16_t)];
    uint8_t tpoly_2t[4][CACHE_SIZE];
    struct gf_poly *f2 = (struct gf_poly*)tpoly_2t[0];
    struct gf_poly *q  = (struct gf_poly*)tpoly_2t[1];
    struct gf_poly *tk = (struct gf_poly*)tpoly_2t[2];
    struct gf_poly *z  = (struct gf_poly*)tpoly_2t[3];
    
    struct gf_poly *gcd;
    
    *g = f;
    *h = NULL;
    
    /* tk = Tr(a^k.X) mod f */
    compute_trace_bk_mod(bch, k, f, z, tk);
    
    
    if (tk->deg > 0)
    {
        /* compute g = gcd(f, tk) (destructive operation) */
        gf_poly_copy(f2, f);
        gcd = gf_poly_gcd(bch, f2, tk);
        
        /*if(max_deg < f2->deg)
         max_deg = f2->deg;*/
        
        if (gcd->deg < f->deg)
        {
            /* compute h=f/gcd(f,tk); this will modify f and q */
            gf_poly_div(bch, f, gcd, q);
            /* store g and h in-place (clobbering f) */
            *h = &((struct gf_poly_deg1 *)f)[gcd->deg].poly;
            gf_poly_copy(*g, gcd);
            gf_poly_copy(*h, q);
            
        }
    }  
}

/*
 * find roots of a polynomial, using BTZ algorithm; see the beginning of this
 * file for details
 */
static int find_poly_roots(struct bch_control *bch, unsigned int k,
                           struct gf_poly *poly, uint16_t *roots)
{
    int cnt;
    struct gf_poly *f1, *f2;
    
    if(poly->deg > bch->t)
        printf("poly->deg=%d\n",poly->deg);
    
    switch (poly->deg) {
            /* handle low degree polynomials with ad hoc techniques */
        case 1:
            cnt = find_poly_deg1_roots(bch, poly, roots);
            break;
        case 2:
            cnt = find_poly_deg2_roots(bch, poly, roots);
            break;
        case 3:
            cnt = find_poly_deg3_roots(bch, poly, roots);
            break;
        case 4:
            cnt = find_poly_deg4_roots(bch, poly, roots);
            break;
        default:
            /* factor polynomial using Berlekamp Trace Algorithm (BTA) */
            cnt = 0;
            if (poly->deg && (k <= GF_M(bch))) {
                factor_polynomial(bch, k, poly, &f1, &f2);
                if (f1)
                    cnt += find_poly_roots(bch, k+1, f1,roots);
                if (f2)
                    cnt += find_poly_roots(bch, k+1, f2,roots+cnt);
            }
            break;
    }
    return cnt;
}

/*
 * generate Galois field lookup tables
 */
static int build_gf_tables(struct bch_control *bch, uint16_t poly)
{
    unsigned int i, x = 1;
    const unsigned int k = 1 << deg(poly);
    
    // printf("poly=%d\n",poly);
    
    /* primitive polynomial must be of degree m */
    if (k != (1u << GF_M(bch)))
        return -1;
    
    for (i = 0; i < GF_N(bch); i++) {
        bch->a_pow_tab[i] = x;
        bch->a_log_tab[x] = i;
        if (i && (x == 1))
        /* polynomial is not primitive (a^i=1 with 0<i<2^m-1) */
            return -1;
        x <<= 1;
        if (x & k)
            x ^= poly;
    }
    bch->a_pow_tab[GF_N(bch)] = 1;
    bch->a_log_tab[0] = 0;
    
    return 0;
}

/*
 * compute generator polynomial remainder tables for fast encoding
 */
static void build_mod8_tables(struct bch_control *bch, const uint8_t *g)
{
    int i, j, d;
    uint8_t data, hi, lo, *tab;
    const int l = BCH_ECC_BYTES(bch);
    const int plen = DIV_ROUND_UP(bch->ecc_bits+1, 8);
    const int ecclen = BCH_ECC_BYTES(bch);//DIV_ROUND_UP(bch->ecc_bits, 8);
    
    
    memset(bch->mod8_tab, 0, 256*l*sizeof(*bch->mod8_tab));
    
    for (i = 0; i < 256; i++)
    {
        /* p(X)=i is a small polynomial of weight <= 8 */
        /* we want to compute (p(X).X^(8*b+deg(g))) mod g(X) */
        tab = bch->mod8_tab + i*l;
        data = i;
        while (data)
        {
            d = deg(data);
            /* subtract X^d.g(X) from p(X).X^(8*b+deg(g)) */
            data ^= g[0] >> (7-d);
            for (j = 0; j < ecclen; j++)
            {
                hi = (d < 7) ? g[j] << (d+1) : 0;
                lo = (j+1 < plen) ? g[j+1] >> (7-d) : 0;
                tab[j] ^= hi|lo;
            }
        }
    }
}
/*
 * build a base for factoring degree 2 polynomials
 */
static int build_deg2_base(struct bch_control *bch)
{
    const int m = GF_M(bch);
    int i, j, r;
    uint16_t sum, x, y, remaining, ak = 0, xi[m];
    
    /* find k s.t. Tr(a^k) = 1 and 0 <= k < m */
    for (i = 0; i < m; i++) {
        for (j = 0, sum = 0; j < m; j++)
            sum ^= a_pow(bch, i*(1 << j));
        
        if (sum) {
            ak = bch->a_pow_tab[i];
            break;
        }
    }
    /* find xi, i=0..m-1 such that xi^2+xi = a^i+Tr(a^i).a^k */
    remaining = m;
    memset(xi, 0, sizeof(xi));
    
    for (x = 0; (x <= GF_N(bch)) && remaining; x++) {
        y = gf_sqr(bch, x)^x;
        for (i = 0; i < 2; i++) {
            r = a_log(bch, y);
            if (y && (r < m) && !xi[r]) {
                bch->xi_tab[r] = x;
                xi[r] = 1;
                remaining--;
                break;
            }
            y ^= ak;
        }
    }
    /* should not happen but check anyway */
    return remaining ? -1 : 0;
}

static void *bch_alloc(size_t size, int *err)
{
    void *ptr;
    
    ptr = malloc(size);
    if (ptr == NULL)
        *err = 1;
    return ptr;
}
/*
 * compute generator polynomial for given (m,t) parameters.
 */
static uint8_t *compute_generator_polynomial(struct bch_control *bch)
{
    const unsigned int m = GF_M(bch);
    const unsigned int t = GF_T(bch);
    int n, err = 0;
    uint16_t i, j, nbits, r;
    uint16_t *roots;
    struct gf_poly *g;
    uint8_t *genpoly,word;
    
    g = (struct gf_poly*)bch_alloc(GF_POLY_SZ(m*t), &err);
    roots = (uint16_t*)bch_alloc((bch->n+1)*sizeof(*roots), &err);
    genpoly = (uint8_t*)bch_alloc(DIV_ROUND_UP(m*t+1, 8)*sizeof(*genpoly), &err);
    
    if (err) {
        free(genpoly);
        genpoly = NULL;
        goto finish;
    }
    
    /* enumerate all roots of g(X) */
    memset(roots , 0, (bch->n+1)*sizeof(*roots));
    for (i = 0; i < t; i++) {
        for (j = 0, r = 2*i+1; j < m; j++) {
            roots[r] = 1;
            r = mod_s(bch, 2*r);
        }
    }
    /* build generator polynomial g(X) */
    g->deg = 0;
    g->c[0] = 1;
    for (i = 0; i < GF_N(bch); i++) {
        if (roots[i]) {
            /* multiply g(X) by (X+root) */
            r = bch->a_pow_tab[i];
            g->c[g->deg+1] = 1;
            for (j = g->deg; j > 0; j--)
                g->c[j] = gf_mul(bch, g->c[j], r)^g->c[j-1];
            
            g->c[0] = gf_mul(bch, g->c[0], r);
            g->deg++;
        }
    }
    /* store left-justified binary representation of g(X) */
    n = g->deg+1;
    i = 0;
    
    while (n > 0) {
        nbits = (n > 8) ? 8 : n;
        for (j = 0, word = 0; j < nbits; j++) {
            if (g->c[n-1-j])
                word |= 1u << (7-j);
        }
        genpoly[i++] = word;
        n -= nbits;
    }
    bch->ecc_bits = g->deg;
    
finish:
    free(g);
    free(roots);
    
    return genpoly;
}

void generate_BCH_paramaters(int m, int t, uint16_t prim_poly,char* filename)
{
    int err = 0;
    uint8_t *genpoly;
    struct bch_control bch;
    
    const int min_m = 5;
    const int max_m = 15;
    
    // default primitive polynomials
    static const uint16_t prim_poly_tab[] = {
        0x25, 0x43, 0x83, 0x11d, 0x211, 0x409, 0x805, 0x1053, 0x201b,
        0x402b, 0x8003,
    };
    
    if ((m < min_m) || (m > max_m))
        //values of m greater than 15 are not currently supported;
        //supporting m > 15 would require changing table base type
        // (uint16_t) and a small patch in matrix transposition
        return;
    
    
    // select a primitive polynomial for generating GF(2^m)
    if (prim_poly == 0)
        prim_poly = prim_poly_tab[m-min_m];
    
    
    
    bch.m = m;
    bch.t = t;
    bch.n = (1 << m)-1;
    bch.ecc_bytes = DIV_ROUND_UP(m*t, 8);
    
    err = build_gf_tables(&bch, prim_poly);
    if (err)
        return;
    
    // use generator polynomial for computing encoding tables
    genpoly = compute_generator_polynomial(&bch);
    if (genpoly == NULL)
        return;
    
    build_mod8_tables(&bch, genpoly);
    free(genpoly);
    
    bch.ecc_bytes = BCH_ECC_BYTES(&bch);
    err = build_deg2_base(&bch);
    
    if (err)
        return;
    
    FILE *fp;
    fp = fopen(filename,"w");
    int i=0;
    fprintf(fp,"#include \"bch_codec.h\"\n\n");
    fprintf(fp,"struct bch_control bch = {");
    fprintf(fp,"%d,%d,%d,%d,%d,\n\n",bch.m,bch.n,bch.t,bch.ecc_bits,bch.ecc_bytes);
    
    
    fprintf(fp,"{");
    for(i=0;i<bch.ecc_bytes*256-1;i++)
        fprintf(fp,"%d,",bch.mod8_tab[i]);
    fprintf(fp,"%d},\n\n",bch.mod8_tab[bch.ecc_bytes*256-1]);
    
    fprintf(fp,"{");
    for(i=0;i<m-1;i++)
        fprintf(fp,"%d,",bch.xi_tab[i]);
    fprintf(fp,"%d},\n\n",bch.xi_tab[m-1]);
    
    fprintf(fp,"{");
    for(i=0;i<bch.n;i++)
        fprintf(fp,"%d,",bch.a_log_tab[i]);
    fprintf(fp,"%d},\n\n",bch.a_log_tab[bch.n]);
    
    fprintf(fp,"{");
    for(i=0;i<bch.n;i++)
        fprintf(fp,"%d,",bch.a_pow_tab[i]);
    fprintf(fp,"%d}\n};",bch.a_pow_tab[bch.n]);
    
    
    fclose(fp);
    
    return;
}

void encode_bch(struct bch_control *bch,const unsigned char *data, uint16_t len, uint8_t *ecc)
{
    int i;
    uint8_t *p;
    const int l = BCH_ECC_BYTES(bch)-1;
    
    while (len--)
    {
        p = bch->mod8_tab + (l+1)*(ecc[0]^(*data++));
        
        for (i = 0; i < l; i++)
            ecc[i] = ecc[i+1]^(*p++);
        ecc[l] = *p;
    }
}

int decode_bch(struct bch_control *bch, const uint8_t *data, uint16_t len,
               const uint8_t *recv_ecc, uint16_t *errloc)
{
    const int ecc_words = BCH_ECC_BYTES(bch);
    unsigned int nbits;
    int i, err, nroots;
    uint8_t sum;
        
    uint8_t cmpt_ecc[CACHE_SIZE]={0};//size < ecc_bytes
    
    encode_bch(bch, data, len, cmpt_ecc);
    
    for (i = 0, sum = 0; i < ecc_words; i++) {
        cmpt_ecc[i] ^= recv_ecc[i];
        sum |= cmpt_ecc[i];
    }
    if (!sum)
    /* no error found */
        return 0;
    
    uint16_t syn[CACHE_SIZE];//size <=2t
    compute_syndromes(bch,cmpt_ecc, syn);
    
    uint8_t telp[3*(bch->t+1)*sizeof(uint16_t)];
    struct gf_poly *elp = (struct gf_poly*)telp;//size <= (t+1)*sizeof(struct gf_poly_deg1)
    err = compute_error_locator_polynomial(bch,elp,syn);
    
    if (err > 0) {
        nroots = find_poly_roots(bch, 1,elp,errloc);
        if (err != nroots)
            err = -1;
    }
    if (err > 0) {
        nbits = (len*8)+bch->ecc_bits;
        for (i = 0; i < err; i++) {
            if (errloc[i] >= nbits) {
                err = -1;
                break;
            }
            errloc[i] = nbits-1-errloc[i];
            errloc[i] = (errloc[i] & ~7)|(7-(errloc[i] & 7));
        }
    }
    return err;
}

/**
 * correct_bch - correct error locations as found in decode_bch
 * @bch,@data,@len,@errloc: same as a previous call to decode_bch
 * @nerr: returned from decode_bch
 */
void correct_bch(uint8_t *data, uint16_t len,uint16_t *errloc, int nerr)
{
    int i;
    for (i=0;i<nerr;++i) {
        int bi = errloc[i];
        if ( (bi>>3) < len)
            data[bi>>3] ^= (1<<(bi&7));
    }
    
}
