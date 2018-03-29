
### Installation

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

Clone and build libkeccak
```
git clone https://github.com/gvanas/KeccakCodePackage.git
cd KeccakCodePackage/
make generic64/libkeccak.a
cd ..
```

Some candidates require the latest 1.1.0 series OpenSSL.  We will download and install it locally
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
