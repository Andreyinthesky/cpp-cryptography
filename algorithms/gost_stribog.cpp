#include "gost_stribog.h"


uint512_t X_map(uint512_t k, uint512_t a) {
	return k ^ a;
}

uint512_t S_map(uint512_t block) {
	uint512_t result;

	for (size_t i = 0; i < block.bits.size(); i++) {
		uint32_t res_part = 0;
		for (int j = 0; j < 4; j++) {
			uint8_t n = (block[i] >> (8 * j)) & 0xff;
			res_part += ((uint32_t)Pi_stribog[n]) << (8 * j);
		}
		result.bits[i] = res_part;
	}

	return result;
}

uint512_t P_map(uint512_t block) {
	uint512_t result;

	for (size_t i = 0; i < block.bits.size(); i++) {
		uint32_t res_part = 0;
		for (int j = 0; j < 4; j++) {
			int number = Tau[4 * i + j];
			uint8_t n = (block[number / 4] >> (8 * (number % 4))) & 0xff;
			res_part += ((uint32_t)n) << (8 * j);
		}
		result.bits[i] = res_part;
	}

	return result;
}

uint512_t L_map(uint512_t block) {
	vector<uint64_t> result_parts;

	for (size_t i = 0; i < 16; i+=2) {
		uint64_t res_part = 0;
		for (int j = 0; j < 64; j++) {
			uint64_t bit = (j >= 32 ? (block[i] >> (31 - j)) : (block[i + 1] >> (63 - j))) & 0x01;
			res_part ^= bit == 0 ? 0 : A[j];
		}

		result_parts.push_back(res_part);
	}

	return result_parts;
}

vector<uint512_t> get_keys(uint512_t K) {
	vector<uint512_t> keys;

	keys.push_back(K);
	for (int i = 1; i < 13; i++) {
		keys.push_back(L_map(P_map(S_map(X_map(keys[i - 1], C[i - 1])))));
	}

	return keys;
}

uint512_t E_map(uint512_t K, uint512_t m) {
	vector<uint512_t> keys = get_keys(K);

	m = X_map(keys[0], m);

	for (int i = 1; i < 13; i++) {
		m = S_map(m);
		m = P_map(m);
		m = L_map(m);
		m = X_map(keys[i], m);
	}

	return m;
}

uint512_t compress(uint512_t N, uint512_t h, uint512_t m) {
	uint512_t K = h ^ N;
	K = S_map(K);
	K = P_map(K);
	K = L_map(K);

	uint512_t t = E_map(K, m);

	return h ^ t ^ m;
}

uint8_t* complete_msg(uint8_t* msg, uint64_t msg_len_in_bits)
{
	uint8_t* res = (uint8_t*)malloc(64 * sizeof(uint8_t));

	for (size_t i = 0; i < 64; i++) {
		res[i] = 0;
	}
	res[(511 - msg_len_in_bits) / 8] |= ((uint8_t)1) << (7 - (511 - msg_len_in_bits) % 8);

	uint64_t j = 0;
	int k = 511 - msg_len_in_bits + 1;

	for ( ; j < msg_len_in_bits; j++) {
		res[k / 8] |= msg[j / 8] >> (7 - j % 8) << (7 - k % 8);
		k++;
	}

	return res;
}

uint512_t take_last_64bytes_from(uint8_t* msg, int last_index) {
	vector<uint64_t> result;

	for (int i = 0; i < 8; i++) {
		uint64_t b = 0;
		for (int j = 0; j < 8; j++) {
			b += ((uint64_t)msg[last_index - (8 * i + j)]) << (8 * j);
		}
		result.push_back(b);
	}

	return result;
}

uint512_t get_hash(uint8_t* msg, uint64_t msg_len_in_bits) {
	uint512_t zero_vector;
	uint512_t h;
	uint512_t N;
	uint512_t Sigma;
	uint512_t m;

	while (msg_len_in_bits >= 512) {
		int msg_last_byte_index = (msg_len_in_bits + (7 - msg_len_in_bits % 8)) / 8 - 1;
		m = take_last_64bytes_from(msg, msg_last_byte_index);

		h = compress(N, h, m);
		N = N + 512;
		Sigma = Sigma + m;

		msg_len_in_bits -= 512;
	}

	//дополнение: 0^(511-|M|) || 1 || M
	msg = complete_msg(msg, msg_len_in_bits);
	m = take_last_64bytes_from(msg, 63);

	h = compress(N, h, m);
	N = N + msg_len_in_bits;
	Sigma = Sigma + m;
	h = compress(zero_vector, h, N);
	h = compress(zero_vector, h, Sigma);

	return h;
}
