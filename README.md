# pqcbench

2018-03-29 Markku-Juhani O. Saarinen, <mjos@iki.fi>

**pqcbench** is a tool for testing properties of the candidates in
[NIST Post-Quantum Cryptography Standardization Effort](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Round-1-Submissions). 

This initial release covers more than 100 variants of 32+ (depending on how you
count) different KEMs. It is my intention to expand the coverage to Public Key
Encryption and Signature algorithms soon. 

Some variants are currently left out from the test suite just because they 
take too long to run (notably bigger variants of Post-Quantum RSA), or just 
because I have not been able to make them run without decryption errors yet. 
There are problems especially with candidates that use the NTL library.

Performance testing is a useful feature, but not the primary function 
of this testing suite. The idea is to enable researchers to perform automated 
testing of algorithm properties across *all* candidates with reasonable ease.
Properties such as time variance, statistical properties of ciphertext,
decryption failure rate, and non-malleability of ciphertext are of particular
interest. Currently provided scripts just time the candidates, but this 
is easily extensible at a single point (`src/kem_test.c`).

I did similar work on the CAESAR AEAD candidates, published as 
[The BRUTUS Automatic Cryptanalytic Framework](http://dx.doi.org/10.1007/s13389-015-0114-1) 
(J. Cryptographic Engineering, Vol. 6, No. 1, pp 75-82. Springer 2016.)

Optimized C implementation was used, when available. Some of the implementation
source code has been heavily hacked to fit the pqcbench mold, and bugs will 
lurk there for a while. 


## Compiling

These instructions are for Debian / Ubuntu - flavoured Linux systems. Hacking
the system to work on, say, Mac OS should not be too difficult, but you may
have to compile more libraries from scratch.

Make sure you have the prerequisite tools and libraries installed:
```
sudo apt install git gcc make xsltproc libssl-dev libgmp-dev libntl-dev
```
 
Fetch (clone) pqcbench itself:

```
git clone https://github.com/mjosaarinen/pqcbench.git
cd pqcbench
```

Fetch and build latest libkeccak:
```
git clone https://github.com/gvanas/KeccakCodePackage.git
cd KeccakCodePackage
make generic64/libkeccak.a
cd ..
```
Some candidates require 1.1 series of OpenSSL libcrypto (notably Lotus).
This is the default with Ubuntu 18.04 but not earlier. 

## Running basic benchmarks

### Key Encapsulation Mechanisms

The main test runner for KEMs is the bash script `test_kems.sh`. It will 
take in a list of KEM directories to be ran and name of the output report file.
You may copy and modify to script to fit your needs -- to change compiler
options etc.

With the default timeout options the script will currently run for about half
an hour while it covers more than a hundred variants listed in 
`testable_kem.lst` (provided):
```
./test_kems.sh testable_kem.lst reports/mysystem-kem.txt
```
The script generates running output to `/dev/tty` in addition to the report 
file at `reports/mysystem-kem.txt`, so redirecting the output of the script 
is pointless. 

The output format is fairly simple. The first column always gives a numeric
timing in seconds. *KEX Total* is simply the sum of time taken by *KEM KeyGen* 
(Key Generation), *KEM Encaps* (Encapsulation), and *KEM Decaps* 
(Decapsulation).
```
       0.000805357 s   KEX Total   [AKCN-MLWE]
       0.000324488 s   KEM KeyGen  [AKCN-MLWE]
       0.000387908 s   KEM Encaps  [AKCN-MLWE]
       0.000092065 s   KEM Decaps  [AKCN-MLWE]
       0.000795337 s   KEX Total   [AKCN-MLWE]
       0.000318946 s   KEM KeyGen  [AKCN-MLWE]
       0.000382831 s   KEM Encaps  [AKCN-MLWE]
       0.000091833 s   KEM Decaps  [AKCN-MLWE]
       0.001336305 s   KEX Total   [AKCN-SEC]
       0.000421219 s   KEM KeyGen  [AKCN-SEC]
       [...]
```
You are expected to use standard UNIX text tools to extract the information
you want from report file. To get a sorted list of total KEX times, for 
example, you can do something like:
```
cd reports
grep "KEX Total" mysystem-kem.txt | sort -n > mysystem-kex.txt
```
This will generate a list of algorithms sorted by Total Key Exchange time.
The output will look something like like:
```
       0.000302187 s   KEX Total   [BabyBearEphem]
       0.000307943 s   KEX Total   [NewHope512-CPAKEM]
       0.000454817 s   KEX Total   [BabyBear]
       0.000515070 s   KEX Total   [NewHope512-CCAKEM]
       0.000516640 s   KEX Total   [MamaBearEphem]
[..]
       8.925089051 s   KEX Total   [BIG_QUAKE_3]
      14.155901973 s   KEX Total   [Classic McEliece 6960119]
      16.505762053 s   KEX Total   [BIG_QUAKE]
      19.538673317 s   KEX Total   [DAGS_3]
     145.986861373 s   KEX Total   [DAGS_5]
```

