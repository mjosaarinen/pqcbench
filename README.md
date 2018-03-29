# pqcbench

**pqcbench** is a tool for testing properties of the candidates in
[NIST Post-Quantum Cryptography Standardization Effort](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Round-1-Submissions). 

This initial release covers 112 variants of 34 (depending on how you count)
different KEMs. It is my intention to expand the coverage to Public Key
Encryption and Signature algorithms soon. 

Performance testing is useful an useful feature, but not the primary function 
of this testing suite. The idea is to enable researchers to perform automated testing of other properties across *all* candidates with reasonable ease.
Properties such as time variance, statistical properties of ciphertext,
decryption failure rate, and non-malleability of ciphertext are of particular
interest. The current version tests just running time.

I did similar work on the CAESAR AEAD candidates, published in 
[The BRUTUS Automatic Cryptanalytic Framework](http://dx.doi.org/10.1007/s13389-015-0114-1) (J. Cryptographic Engineering, Vol. 6, No. 1, pp 75-82. Springer 2016.)

Optimized C implementation was used, when available. Some of the implementation
source code has been heavily hacked to fit the pqcbench mold, and bugs will 
lurk there for a while. 

**Cheers,**

-Markku 

## Installation

Make sure you have basic packages required. As a superuser:
```
apt install git gcc make xsltproc openssl libssl-dev
```
 
Now as a normal user we may clone pqcbench and install its particular
requirements locally

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
Some candidates require 1.1 series of OpenSSL libcrypto.
If you are using an Ubuntu older than the 18.04 release, you
will gave to download and install it locally:
```
wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz
tar xfvz openssl-1.1.0g.tar.gz 
cd openssl-1.1.0g
./config -static
make
mv libcrypto.a ..
rm -rf ../include/openssl
mv include ..
cd ..
rm -rf openssl-*
```

## Running basic benchmarks

### Key Encapsulation Mechanisms

The main test runner for KEMs is the bash script `test_kems.sh`. It will 
take in a list of KEM directories to be ran and name of the output report file.
You may copy and modify to script to fit your needs -- to change compiler
options etc.

With the default timeout options the script will currently run for about half
an hour while it covers 112 variants:
```
./test_kems.sh testable_kem.lst reports/mysystem-kem.txt
```
The script generates running output to `/dev/tty` in addition to the report 
file, so redirecting the output of the script is pointless.

The output format is fairly simple. The first column always gives a numeric
timing in seconds. *KEX Total* is simply the sum of time taken by *KEM KeyGen* (Key Generation), *KEM Encaps* (Encapsulation), and *KEM Decaps* 
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
``
You are expected to use standard UNIX text manipulation tools to manipulate
the report file. To get a sorted list of total KEX times, for example, you
can do something like:
```
$ cd reports
$ grep "KEX Total" mysystem-kem.txt | sort -n > mysystem-kex.txt
```
This will generate a list of algorithms sorted by Total Key Exchangee time.

