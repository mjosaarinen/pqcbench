##########################################################################
#Lepton: LPN-based public KEM scheme
#Author: Yu Yu and Jiang Zhang
#The program was implemented by Jiang Zhang (jiangzhang09@gmail.com)
#
#
###########################################################################
#Requires: the host should have installed the openssl library
#which will be used by the randomness generation subroutines
#By default, the program set the path to openssl directories as: 
#/usr/local/include and /usr/local/lib
#
#If openssl is not installed in the above directories, 
#one has to pass the INC=-I/path_to_openssl_header
#and LIB=-L/path_to_openssl_lib to the make procedure:
#
#
make INC=-I/path_to_openssl_header  LIB=-L/path_to_openssl_lib
make test
make kat
#
#Else, one can have a quick start, using the following commands 
#
make
make test
make kat

#This will build the program, test the performance 
#and generate the kat files. By default, the make 
#procedure will build the Lepton.CCA program using 
#using the Moderate I parameter set. One can change 
#the algorithm by passing the ALGOR flag:
#
make ALGOR=-DLEPTON_CCA   #building Lepton.CCA
# or 
make ALGOR=-DLEPTON_CPA   #building Lepton.CPA
#
##########################################################################
#One can also set different parameter set for the program
#by passing the PARAM flag to the make procedure:
#set the Light I parameter set
make PARAM=-DLIGHT_I
# or 
#set the Light II parameter set
make PARAM=-DLIGHT_II
# or 
#set the Moderate I parameter set
make PARAM=-DMODER_I
# or 
#set the Moderate II parameter set
make PARAM=-DMODER_II
# or 
#set the Moderate III parameter set
make PARAM=-DMODER_III
# or 
#set the Moderate IV  parameter set
make PARAM=-DMODER_IV
# or 
#set the Paranoid I parameter set
make PARAM=-DPARAN_I
# or 
#set the Paranoid II parameter set
make PARAM=-DPARAN_II

##########################################################################
#Finally, one can combine all the above flags in a single command line:
make PARAM=-DMODER_IV  ALGOR=-DLEPTON_CPA INC=-I/path_to_openssl_header  LIB=-L/path_to_openssl_lib

