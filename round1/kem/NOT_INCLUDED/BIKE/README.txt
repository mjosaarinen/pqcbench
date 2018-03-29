
BIKE reference and optimized implementations assume that OpenSSL and NTL libraries are available in the platform.

To compile this code for NIST KAT routine: make bike-nist-kat
To compile this code for demo tests: make bike-demo-test

TO EDIT PARAMETERS AND SELECT THE BIKE VARIANT: please edit defs.h file in the indicated sections.

The file measurements.h controls how the cycles are counted. Note that #define REPEAT is initially set to 100, 
which means that every keygen, encaps and decaps is repeated 100 times and the number of cycles is averaged.

