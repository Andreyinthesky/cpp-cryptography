#include "../algorithms/gost_magma.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <ctime>

/////////////////////// MISC /////////////////////////////


using std::cout;
using std::cin;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::vector;
using std::string;

//////////////////////////////////////////////////////////

uint64_t decrypt(uint64_t block, vector<uint32_t> keys) {
	for (int i = ITER_COUNT - 1; i > 0; i--) {
		uint64_t left = block >> 32;
		uint64_t right = block & ((((uint64_t) 1) << 32) - 1);
		uint64_t temp = (right << 32) + (g_map(right, keys[i]) ^ left);

		block = temp;
	}

	uint64_t left = block >> 32;
	uint64_t right = block & ((((uint64_t) 1) << 32) - 1);
	uint64_t temp = ((g_map(right, keys[0]) ^ left) << 32) + right;

	block = temp;

	return block;
}

uint64_t encrypt(uint64_t block, vector<uint32_t> keys) {
	for (int i = 0; i < ITER_COUNT - 1; i++) {
		uint64_t left = block >> 32;
		uint64_t right = block & (((uint64_t) 1 << 32) - 1);
		uint64_t temp = (right << 32) + (g_map(right, keys[i]) ^ left);

		block = temp;
	}

	uint64_t left = block >> 32;
	uint64_t right = block & (((uint64_t) 1 << 32) - 1);
	uint64_t temp = ((g_map(right, keys[ITER_COUNT - 1]) ^ left) << 32)
			+ right;


	block = temp;

	return block;
}

uint64_t g_map(uint64_t R, uint64_t key) {
	uint32_t a = (R + key);
	uint32_t t = t_map(a);
	return (t << 11) | (t >> (32 - 11));
}

uint32_t t_map(uint32_t a) {
	vector<uint8_t> t_parts;

	for (int i = 0; i < 4; i++) {
		uint8_t a_part = (a >> (i*8)) & 0xff;
		uint8_t left_a_part = a_part >> 4;
		uint8_t right_a_part = a_part & 0x0f;

		uint8_t t_part = (Pi[2*i+1][left_a_part] << 4)
				+ Pi[2*i][right_a_part];

		t_parts.push_back(t_part);
	}

	uint32_t t = 0;
	for (int i = t_parts.size() - 1; i >= 0; i--) {
		t += ((uint32_t)t_parts[i]) << (i*8);
	}

	return t;
}
