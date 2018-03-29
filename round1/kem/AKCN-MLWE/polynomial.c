

#include "polynomial.h"

#include "reduce.h"
#include "rng.h"
#include "akcn.h"
#include <stdlib.h>
#include <string.h>

// this table defines the visited order in the NTT multiplication.
// In this implementation, we have n = 256.
const uint16_t reverse_order_table[MLWE_N] = {0, 128, 64, 192, 32, 160, 96, 224, 16, 144, 80, 208, 48, 176, 112, 240, 8, 136, 72, 200, 40, 168, 104, 232, 24, 152, 88, 216, 56, 184, 120, 248, 4, 132, 68, 196, 36, 164, 100, 228, 20, 148, 84, 212, 52, 180, 116, 244, 12, 140, 76, 204, 44, 172, 108, 236, 28, 156, 92, 220, 60, 188, 124, 252, 2, 130, 66, 194, 34, 162, 98, 226, 18, 146, 82, 210, 50, 178, 114, 242, 10, 138, 74, 202, 42, 170, 106, 234, 26, 154, 90, 218, 58, 186, 122, 250, 6, 134, 70, 198, 38, 166, 102, 230, 22, 150, 86, 214, 54, 182, 118, 246, 14, 142, 78, 206, 46, 174, 110, 238, 30, 158, 94, 222, 62, 190, 126, 254, 1, 129, 65, 193, 33, 161, 97, 225, 17, 145, 81, 209, 49, 177, 113, 241, 9, 137, 73, 201, 41, 169, 105, 233, 25, 153, 89, 217, 57, 185, 121, 249, 5, 133, 69, 197, 37, 165, 101, 229, 21, 149, 85, 213, 53, 181, 117, 245, 13, 141, 77, 205, 45, 173, 109, 237, 29, 157, 93, 221, 61, 189, 125, 253, 3, 131, 67, 195, 35, 163, 99, 227, 19, 147, 83, 211, 51, 179, 115, 243, 11, 139, 75, 203, 43, 171, 107, 235, 27, 155, 91, 219, 59, 187, 123, 251, 7, 135, 71, 199, 39, 167, 103, 231, 23, 151, 87, 215, 55, 183, 119, 247, 15, 143, 79, 207, 47, 175, 111, 239, 31, 159, 95, 223, 63, 191, 127, 255};  


/*
	This table defines the exponenets of phi used in the the negative wrapped convolution method, with slight difference. 
	In this implementation, we have q = 7681, n = 256; 
	And phi = 7146 is a primitive (2n)-th root of unity in Fq*.
	
	The former part of the table phi_table[0..n-1] is used in the pre-computation of the negative wrapped convolution method.
	When 0<=j<n, phi_table[j] = (phi^j * R^2) mod q. 
	Here, R=2^18 is used in REDC algorithm.
	
	The latter part of the table phi_table[n..(2n-1)] is used in the post-computation of the negative wrapped convlution method.
	When n<=j<2n, phi_table[j] = (phi^(2n-1-j)*1/n) mod q. 
*/
const uint16_t phi_table[2*MLWE_N] = {4613, 5327, 7387, 3670, 2886, 7552, 7567, 7223, 6919, 577, 6226, 2644, 6445, 694, 5079, 1809, 7672, 4815, 4791, 2269, 7364, 613, 2328, 6523, 5050, 1962, 2627, 178, 4623, 7658, 4624, 7123, 6652, 5164, 2420, 3389, 7282, 6078, 5014, 5860, 6429, 1573, 3355, 2429, 6255, 2491, 3809, 5331, 5247, 4101, 2731, 5986, 467, 3628, 2313, 6867, 5354, 623, 4659, 3760, 822, 5728, 239, 2712, 789, 340, 2444, 5911, 2187, 5148, 3299, 1665, 221, 4661, 2690, 4878, 1810, 7137, 6843, 2832, 5718, 5589, 5475, 5017, 4255, 4832, 3377, 6021, 4785, 5479, 2877, 4686, 4677, 1811, 6602, 1190, 873, 1486, 3814, 2656, 25, 1987, 4614, 4792, 1734, 1711, 6335, 5777, 4748, 2231, 4651, 359, 7641, 6038, 3371, 1550, 298, 1871, 5226, 7655, 6229, 1039, 4848, 2498, 64, 4165, 6896, 5201, 5668, 1615, 3928, 3114, 787, 1410, 6069, 2148, 2970, 1017, 1256, 3968, 4757, 5097, 7541, 5771, 277, 5425, 1043, 2708, 2929, 7590, 2599, 7477, 1606, 1062, 224, 3056, 1093, 6682, 4476, 1812, 6067, 3218, 6595, 4935, 2039, 7518, 2714, 7400, 4396, 6207, 5128, 6318, 7191, 996, 4810, 7466, 7491, 1797, 6411, 3522, 5256, 6967, 5621, 3717, 784, 3015, 7666, 344, 304, 6342, 2032, 3582, 3880, 5751, 3296, 3270, 1818, 2857, 24, 2522, 2586, 6751, 5966, 3486, 1473, 3088, 7016, 2449, 3236, 4646, 3034, 5182, 471, 1488, 2744, 6712, 3788, 1204, 1064, 6835, 7112, 4856, 5899, 926, 3855, 3764, 6363, 6159, 84, 1146, 1370, 4426, 5519, 4520, 1315, 3127, 1513, 4731, 3645, 899, 2938, 2775, 5489, 5208, 1923, 449, 5577, 4214, 3724, 4720, 1849, 1634, 1444, 3241, 1971, 5493, 6993, 7073, 2678, 3617, 517, 7602, 3860, 1089, 1141, 4045, 1967, 7633, 2637, 2509, 1860, 3430, 709, 4735, 1505, 1330, 2783, 1209, 6070, 1613, 4998, 6739, 4705, 2193, 1938, 105, 5273, 5553, 1692, 1138, 5650, 3564, 5829, 7652, 153, 2636, 3044, 7513, 5389, 4941, 6510, 4324, 6322, 5051, 1427, 4655, 5900, 391, 5883, 1805, 2131, 4384, 4946, 3835, 6783, 4208, 6934, 233, 5922, 3983, 4413, 4793, 1199, 3739, 4376, 1545, 2973, 7093, 7340, 5772, 7423, 7453, 6765, 6157, 1154, 4771, 5288, 5209, 1388, 2477, 3618, 7663, 1949, 1901, 4538, 7047, 1226, 4656, 5365, 2419, 3924, 5254, 356, 1565, 7635, 1567, 6565, 5623, 2647, 4840, 6778, 6883, 4475, 2347, 4039, 5177, 3146, 6710, 4858, 4829, 4982, 7618, 2981, 2813, 521, 5462, 4291, 934, 7256, 4626, 6053, 3027, 1246, 1637, 7520, 1644, 3775, 478, 5424, 1578, 680, 4888, 4141, 4374, 2615, 6598, 3330, 442, 1641, 5380, 2075, 3620, 6593, 6005, 5664, 3755, 3497, 3269, 2353, 829, 1983, 6754, 4361, 1889, 3277, 5754, 1691, 1673, 3622, 5523, 2380, 1746, 2972, 7628, 5312, 50, 3974, 1547, 1903, 3468, 3422, 4989, 3873, 1815, 4462, 1621, 718, 7601, 4395, 6742, 3100, 596, 3742, 2771, 7629, 4777, 2078, 2015, 4996, 128, 649, 6111, 2721, 3655, 3230, 175, 6228, 1574, 2820, 4457, 4296, 5940, 2034, 2512, 255, 1833, 2513, 7401, 3861, 554, 3169, 2086, 5416, 5858, 7499, 5198, 7273, 3212, 2124, 448, 6112, 2186, 5683, 1271, 3624, 4453, 6436, 5509, 2189, 4078, 7355, 5428, 7119, 1111, 4733, 2575, 4955, 6701, 1992, 1939, 7251, 7301, 3594, 5141, 7044, 2831, 6253, 3561, 7434, 1568, 6030, 7651};


/*
	This tables is used in the bufferfly operation of the NTT transform and the inverse NTT transform.
	In this implementation, we have q = 7681, n = 256; 
	And omega = 2028 is a primitive (n)-th root of unity in Fq*. 
	
	For every 0<=j<n/2, we have omega_table[j] = (omega^j mod q);
	For every n/2<=j<n, we have omega_table[j] = (omgea^(j+1) mod q). 
*/
const uint16_t omega_table[MLWE_N] = {1, 2028, 3449, 4862, 5413, 1415, 4607, 2900, 5235, 1438, 5165, 5417, 1846, 3041, 6986, 3844, 7098, 550, 1655, 7424, 1112, 4603, 2469, 6801, 5033, 6556, 7438, 6461, 6803, 1408, 5773, 1800, 1925, 1952, 2941, 3892, 4589, 4801, 4601, 6094, 7584, 2990, 3411, 4608, 4928, 1003, 6300, 2897, 6832, 6453, 5941, 4540, 5282, 4582, 5967, 3501, 2784, 417, 766, 1886, 7351, 6688, 6299, 869, 3383, 1591, 528, 3125, 675, 1682, 732, 2063, 5300, 2681, 6601, 6526, 365, 2844, 6882, 319, 1728, 1848, 7097, 6203, 5887, 2562, 3380, 3188, 5543, 3901, 7479, 5118, 2273, 1044, 4957, 6048, 6468, 5637, 2508, 1402, 1286, 4149, 3477, 198, 2132, 6974, 2551, 4115, 3654, 5828, 5806, 7276, 527, 1097, 4907, 4501, 3000, 648, 693, 7462, 1366, 5088, 2881, 5108, 5036, 4959, 2423, 5685, 5653, 4232, 2819, 2268, 6266, 3074, 4781, 2446, 6243, 2516, 2264, 5835, 4640, 695, 3837, 583, 7131, 6026, 257, 6569, 3078, 5212, 880, 2648, 1125, 243, 1220, 878, 6273, 1908, 5881, 5756, 5729, 4740, 3789, 3092, 2880, 3080, 1587, 97, 4691, 4270, 3073, 2753, 6678, 1381, 4784, 849, 1228, 1740, 3141, 2399, 3099, 1714, 4180, 4897, 7264, 6915, 5795, 330, 993, 1382, 6812, 4298, 6090, 7153, 4556, 7006, 5999, 6949, 5618, 2381, 5000, 1080, 1155, 7316, 4837, 799, 7362, 5953, 5833, 584, 1478, 1794, 5119, 4301, 4493, 2138, 3780, 202, 2563, 5408, 6637, 2724, 1633, 1213, 2044, 5173, 6279, 6395, 3532, 4204, 7483, 5549, 707, 5130, 3566, 4027, 1853, 1875, 405, 7154, 6584, 2774, 3180, 4681, 7033, 6988, 219, 6315, 2593, 4800, 2573, 2645, 2722, 5258, 1996, 1};


/*
	This tables is used in the bufferfly operation of the NTT transform and the inverse NTT transform.
	In this implementation, we have q = 7681, n = 256; 
	And omega = 2028 is a primitive (n)-th root of unity in Fq*. 
	
	For every j, translated_omega_table[j] = floor(omega_table[j] * 2^16 / q). 
*/
const uint16_t translated_omega_table[MLWE_N] = {8, 17303, 29427, 41483, 46184, 12073, 39307, 24743, 44666, 12269, 44068, 46219, 15750, 25946, 59606, 32797, 60561, 4692, 14120, 63343, 9487, 39273, 21066, 58027, 42942, 55937, 63462, 55126, 58044, 12013, 49256, 15358, 16424, 16654, 25093, 33207, 39154, 40963, 39256, 51995, 64708, 25511, 29103, 39316, 42046, 8557, 53753, 24717, 58292, 55058, 50689, 38736, 45067, 39094, 50911, 29871, 23753, 3557, 6535, 16091, 62720, 57063, 53744, 7414, 28864, 13574, 4505, 26663, 5759, 14351, 6245, 17601, 45220, 22874, 56321, 55681, 3114, 24265, 58718, 2721, 14743, 15767, 60553, 52925, 50229, 21859, 28838, 27200, 47294, 33284, 63812, 43667, 19393, 8907, 42294, 51602, 55186, 48096, 21398, 11962, 10972, 35400, 29666, 1689, 18190, 59503, 21765, 35110, 31176, 49725, 49538, 62080, 4496, 9359, 41867, 38403, 25596, 5528, 5912, 63667, 11655, 43411, 24581, 43582, 42968, 42311, 20673, 48505, 48232, 36108, 24052, 19351, 53462, 26228, 40792, 20869, 53266, 21467, 19316, 49785, 39589, 5929, 32738, 4974, 60843, 51415, 2192, 56048, 26262, 44469, 7508, 22593, 9598, 2073, 10409, 7491, 53522, 16279, 50177, 49111, 48881, 40442, 32328, 26381, 24572, 26279, 13540, 827, 40024, 36432, 26219, 23489, 56978, 11782, 40818, 7243, 10477, 14846, 26799, 20468, 26441, 14624, 35664, 41782, 61978, 59000, 49444, 2815, 8472, 11791, 58121, 36671, 51961, 61030, 38872, 59776, 51184, 59290, 47934, 20315, 42661, 9214, 9854, 62421, 41270, 6817, 62814, 50792, 49768, 4982, 12610, 15306, 43676, 36697, 38335, 18241, 32251, 1723, 21868, 46142, 56628, 23241, 13933, 10349, 17439, 44137, 53573, 54563, 30135, 35869, 63846, 47345, 6032, 43770, 30425, 34359, 15810, 15997, 3455, 61039, 56176, 23668, 27132, 39939, 60007, 59623, 1868, 53880, 22124, 40954, 21953, 22567, 23224, 44862, 17030, 8};


// It generates a noise polynomial according to "noise_seed+nonce".
void Get_small_poly(
		Polynomial * ptr, 
		const unsigned char noise_seed[NOISE_SEED_BYTES], 
		const unsigned int nonce)
{
	uint16_t i,j;
	uint8_t temp;

	unsigned char string[NOISE_SEED_EXPAND_BYTES];

	{{ // generate the pseudorandom string
		unsigned char diversifier[8] = {1,2,3,4,5,6,7,8};
       	unsigned char local_seed[NOISE_SEED_BYTES+1];

		memcpy(local_seed, noise_seed, NOISE_SEED_BYTES);
      	local_seed[NOISE_SEED_BYTES] = nonce;

       	AES_XOF_struct aes_state;
		seedexpander_init(&aes_state, local_seed, diversifier, 2048);
		seedexpander(&aes_state, string, NOISE_SEED_EXPAND_BYTES);
	}}

	// every pseudorandom byte could be used to generate two small noise coefficients. 
	for(i=0; i<MLWE_N; i+=2)
		for(temp=string[i/2], j=0; j<2; j++,temp>>=4)
			ptr->coefficients[i+j] = MLWE_Q+(temp&0x1)-((temp&0x2)>>1)+((temp&0x4)>>2)-((temp&0x8)>>3);
}


// it performs the pre-computation in the negative wrapped convolution method.
// Note: since phi_table[i] contains an extra R^2 factor initially, this function makes every coefficient in ptr contain an extra R factor finally. 
void Poly_pre_NTT_computation(Polynomial * ptr)
{
	for(uint16_t i=0; i<MLWE_N; i++)
		ptr->coefficients[i] = REDC(phi_table[i] * ptr->coefficients[i]);
}


// It performs the post-computation phase in the negative wrapped convolution method by invoking REDC algorithm.
// Note: initially every coefficient in ptr contains an extra R=2^18 factor.
void Poly_post_NTT_computation(Polynomial * ptr)
{	
	for(uint16_t i=0; i<MLWE_N; i++)
		ptr->coefficients[i] = REDC(ptr->coefficients[i] * phi_table[2*MLWE_N-1-i]);
}


// It computes the componentwise multiplication of a and b by invoking REDC algorithm, and stores their product in product
// Note: since every coefficient in both a and b contains an extra R=2^18, 
// This makes every coefficient in product contains an extra R=2^18 as well.
void Poly_NTT_componentwise_multiply(Polynomial * product, const Polynomial * a, const Polynomial * b)
{
	for(uint16_t i=0; i<MLWE_N; i++)
		product->coefficients[i] = REDC(a->coefficients[i] * b->coefficients[i]);
}


/*
	It performs the NTT transform on ptr when direction=1, 
	and performs the inverse NTT transform on ptr when direction=-1.
	
	Note: every coefficient in ptr contains an extra R factor initially.
*/
void Poly_NTT_transform(Polynomial * ptr, const int direction)
{
	unsigned int base = 0;

	unsigned int m = MLWE_N/2, interval_length = 1;

	unsigned int i,j,k, temp, index;

	if(direction == -1)
		base = MLWE_N-1;	

	for(i=0; i<LOG2N; i++, interval_length<<=1,m>>=1)
		for(j=0; j<interval_length; j++)
			for(temp=2*j*m, index=k=0; k<m; k++, index += interval_length)
				Butterfly(
					&(ptr->coefficients[temp + k]), 
					&(ptr->coefficients[temp + k+m]), 
					base + direction * index
				);

	for(i=0; i<MLWE_N; i++)
	{
		j = reverse_order_table[i];
		if(i < j)
		{
			temp = ptr->coefficients[i];
			ptr->coefficients[i] = ptr->coefficients[j];
			ptr->coefficients[j] = temp;
		}
	}
}


// It performs the butterfly opertion on X and Y
// After: [X,Y] := [X+Y, (X-Y)*omega_table[index]]
void Butterfly(unsigned int * X, unsigned int * Y, unsigned int index)
{
	unsigned int difference = *X - *Y + 2*MLWE_Q;
	unsigned int temp = (translated_omega_table[index] * difference) >> K_IN_BUTTERFLY; 

	*X = Mod2Q(*X+*Y);

	*Y = ((1<<K_IN_BUTTERFLY)-1) & (omega_table[index] * difference - temp * MLWE_Q);
}


// It computes sum = sum+a, and then converts sum into truncated form if necessary (when b=1).
void Poly_add_then_truncate(Polynomial *sum, const Polynomial *a, unsigned int b)
{
	unsigned int temp;

	for(unsigned int i=0; i<MLWE_N; i++)
	{
		temp = Mod2Q(a->coefficients[i] + sum->coefficients[i]);
		if(b>0)
			sum->coefficients[i] = (ModQ(temp)+(1<<(MLWE_T-1)))>>MLWE_T;
		else
			sum->coefficients[i] = ModQ(temp);
	}
}


// It converts the given polynomial into truncated form. 
// Before: every polynomial coefficient is in [0, 2q-1]
// After: every polynomial coefficient is in [0, q/2^t]
void Poly_truncate(Polynomial * ptr)
{
	unsigned int temp;

	for(unsigned int i=0; i<MLWE_N; i++)
	{
		temp = ModQ(ptr->coefficients[i]);
		ptr->coefficients[i] = (temp + (1<<(MLWE_T-1))) >> MLWE_T;
	}
}


// It converts the given truncated polynomial back, by multiplying every coefficient with 2^t.
void Poly_detruncate(Polynomial * ptr)
{
	for(unsigned int i=0; i<MLWE_N; i++)
		ptr->coefficients[i] = ptr->coefficients[i] << MLWE_T;
}


// It computes Signal[...] <- Con(ptr.coefficients[...], key[...]) in the componentwise manner
void Poly_AKCN_Con(
		unsigned int signal[MLWE_N],
		const Polynomial * ptr,
		const unsigned int key[MLWE_N])
{
	for(unsigned int i=0; i<MLWE_N; i++)
		signal[i] = AKCN_Con(ptr->coefficients[i], key[i]);
}


// It computes key[...] <- Rec(ptr->coefficients[...], signal[...]) in the componentwise manner
void Poly_AKCN_Rec(
		unsigned int key[MLWE_N], 
		const Polynomial * ptr, 
		const unsigned int signal[MLWE_N])
{	
	for(unsigned int i=0; i<MLWE_N; i++)
		key[i] = AKCN_Rec(ptr->coefficients[i], signal[i]);
}
