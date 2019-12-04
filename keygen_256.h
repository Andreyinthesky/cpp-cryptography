#ifndef KEYGEN_256_H_
#define KEYGEN_256_H_

#include "algorithms/gost_stribog.h"

class KeyGen256 {
public:
	const static int blocks_count = 256 / (8 * sizeof(uint32_t));

	static vector<uint32_t> gen_key() {
		int n = 8;
		vector<uint32_t> key;
		std::minstd_rand rnd(time(0));

		for (int i = 0; i < n; i++) {
			key.push_back(((uint32_t) rnd()));
		}

		return key;
	}

	//PBKDF
	static vector<uint32_t> gen_key(string password, HashLength hash_length = HashLength::b512) {
		vector<uint32_t> key;
		int c = 12;

		vector<uint8_t> sequence = get_sequence(password);
		sequence.push_back(0x80);
		for (size_t i = 0; i < 3; i++) {
			sequence.push_back(0);
		}

		uint512_t state = get_hash(&sequence[0], sequence.size() * 8);

		for (int i = 1; i < c; i++) {
			sequence = get_sequence(password, (string)state);
			state = state ^ get_hash(&sequence[0], sequence.size() * 8);
		}

		for (size_t i = 0; i < blocks_count && i < state.size(); i++) {
			key.push_back(state[state.size() - i - 1]);
		}

		return key;
	}

private:
	static vector<uint8_t> get_sequence(string password, string salt = "") {
		vector<uint8_t> sequence;

		for (size_t i = 0; i < password.length(); i++) {
			sequence.push_back(password[i]);
		}

		for (size_t i = 0; i < salt.length(); i++) {
			sequence.push_back(salt[i]);
		}

		return sequence;
	}
};


#endif /* KEYGEN_256_H_ */
