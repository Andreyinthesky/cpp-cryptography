#ifndef CRYPTER_H_
#define CRYPTER_H_

#include "key_provider.h"
#include "main.h"

class Crypter {

public:
	ChipherMode mode;
	KeyProvider* key_provider;

	Crypter(KeyProvider* key_provider, ChipherMode mode) {
		this->key_provider = key_provider;
		this->mode = mode;
	}

	void encrypt_file(string file_path) {
		ifstream in;
		ofstream out;
		std::minstd_rand rnd(time(0));

		in.open(file_path, std::ios_base::binary | std::ios_base::ate);
		if (!in.is_open()) {
			throw "Can't open file — " + file_path;
		}

		out.open(file_path + ".enc", std::ios_base::binary);
		uint64_t init_vec = 0;
		vector<uint32_t> keys = get_iter_keys(key_provider->get_key());
		if (mode != ChipherMode::ECB) {
			init_vec = ((uint64_t)rnd()) << 32;
			init_vec += ((uint64_t)rnd());
		}

		uint64_t file_size = in.tellg();
		in.seekg(0);

		if (file_size == 0)
			return;

		cout << "Start encrypt " + file_path << endl;

		// 1 block - file size
		out.write(reinterpret_cast<char*>(&file_size), sizeof(file_size));
		// 2 block - init vector (IV)
		out.write(reinterpret_cast<char*>(&init_vec), sizeof(init_vec));

		uint64_t blocks_count = file_size / 8  + (file_size % 8 != 0 ? 1 : 0);
		uint64_t block;
		uint64_t block_enc;
		int counter = 0;

		for (uint64_t i = 0; i < blocks_count; i++) {
			block = 0;
			in.read(reinterpret_cast<char*>(&block), sizeof(block));

			if (mode != ChipherMode::CTR) {
				block = block ^ init_vec;
				block_enc = encrypt(block, keys);
			} else {
				block_enc = encrypt(init_vec + counter++, keys) ^ block;
			}

			if (mode == ChipherMode::CBC)
				init_vec = block_enc;

			out.write(reinterpret_cast<char*>(&block_enc), sizeof(block_enc));
		}

		in.close();
		out.close();

		cout << "Encrypted file is " + file_path + ".enc" << endl;
	}

	void decrypt_file(string file_path) {
		ifstream in;
		ofstream out;
		vector<uint32_t> keys = get_iter_keys(key_provider->get_key());

		in.open(file_path, std::ios_base::binary | std::ios_base::ate);
		if (!in.is_open()) {
			throw "Can't open file — " + file_path;
		}

		out.open(file_path + ".dec", std::ios_base::binary);
		uint64_t file_size = in.tellg();
		in.seekg(0);

		if (file_size == 0)
			return;

		cout << "Start decrypt " + file_path << endl;

		uint64_t src_file_size = 0;
		uint64_t init_vec = 0;
		in.read(reinterpret_cast<char*>(&src_file_size), sizeof(src_file_size));
		in.read(reinterpret_cast<char*>(&init_vec), sizeof(init_vec));

		uint64_t block;
		uint64_t block_dec;
		int counter = 0;

		for (uint64_t i = 0; i < (src_file_size - src_file_size % 8) / 8; i++) {
			block = 0;
			in.read(reinterpret_cast<char*>(&block), sizeof(block));

			if (mode != ChipherMode::CTR)
				block_dec = decrypt(block, keys) ^ init_vec;
			else
				block_dec = encrypt(init_vec + counter++, keys) ^ block;

			if (mode == ChipherMode::CBC)
				init_vec = block;

			out.write(reinterpret_cast<char*>(&block_dec), sizeof(block_dec));
		}

		if (src_file_size % 8 != 0) {
			block = 0;
			in.read(reinterpret_cast<char*>(&block), sizeof(block));

			if (mode != ChipherMode::CTR)
				block_dec = decrypt(block, keys) ^ init_vec;
			else
				block_dec = encrypt(init_vec + counter++, keys) ^ block;

			out.write(reinterpret_cast<char*>(&block_dec), src_file_size % 8);
		}

		in.close();
		out.close();

		cout << "Decrypted file is " + file_path + ".dec" << endl;
	}

private:
	static vector<uint32_t> get_iter_keys(vector<uint32_t> key) {
		const int count = key.size();
		vector<uint32_t> iter_keys;

		for (int i = 0; i < 3; i++) {
			for (int j = 0; j < count; j++) {
				iter_keys.push_back(key[j]);
			}
		}

		for (int i = count - 1; i >= 0; i--) {
			iter_keys.push_back(key[i]);
		}

		return iter_keys;
	}
};



#endif /* CRYPTER_H_ */
