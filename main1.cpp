#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <ctime>
#include <map>
#include <cstring>
#include <windows.h>

/////////////////////// MISC /////////////////////////////

#include "algorithms/gost_stribog.h"
#include "algorithms/gost_magma.h"

using std::cout;
using std::cin;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::iostream;
using std::fstream;
using std::vector;
using std::string;

//////////////////////////////////////////////////////////

enum ChipherMode {
	ECB = 0,
	CBC,
	CTR
};

ChipherMode get_chipher_mode_from_str(string str) {
		if (str == "ecb") return ChipherMode::ECB;
		else if (str == "ctr") return ChipherMode::CTR;
		else if (str == "cbc") return ChipherMode::CBC;

		throw "Error in get_chipher_mode_from_str";
}

HashLength get_hash_length_from_str(string str) {
		if (str == "512") return HashLength::b512;
		else if (str == "256") return HashLength::b256;

		throw "Error in get_hash_length_from_str";
}

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

		for (int i = 0; i < blocks_count && i < state.bits.size(); i++) {
			key.push_back(state[state.bits.size() - i - 1]);
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

class KeyProvider {
protected:
	KeyProvider() {}

public:
	virtual vector<uint32_t> get_key() = 0;
};

class FileKeyProvider : public KeyProvider {
public:
	string key_file_path;

	FileKeyProvider(string key_file_path) {
		this->key_file_path = key_file_path;
	}

	vector<uint32_t> get_key() override {
		ifstream in;
		vector<uint32_t> keys;

		in.open(key_file_path, std::ios_base::binary);

		if (!in.is_open()) {
			throw "Can't open file — " + key_file_path;
		}

		uint32_t iter_key;
		while(in.read(reinterpret_cast<char*>(&iter_key), sizeof(iter_key))) {
			keys.push_back(iter_key);
		}

		return keys;
	}
};

class PassKeyProvider : public KeyProvider {
public:
	string password;
	HashLength hash_length;

	PassKeyProvider(string password, HashLength hash_length) {
		this->password = password;
		this->hash_length = hash_length;
	}

	vector<uint32_t> get_key() override {
		return KeyGen256::gen_key(password);
	}
};

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

enum HelpMode {
	Default,
	Key,
	Pass,
};

void print_help(HelpMode help_mode = HelpMode::Default, string msg = "") {
	if (!msg.empty())
		cout << msg << endl;

	if (help_mode == HelpMode::Default) {
		cout << "-f - file path {Required}" << endl
			 <<	"-r - decipher mode" << endl
			 << "-m - mode [keygen, key, pass] {Required}" << endl
			 << "-h - help" << endl;
	}
	else if (help_mode == HelpMode::Key) {
		cout <<	"-m key (Cipher/Decipher mode with key located in file)" << endl
			 << "-c - cipher mode [ecb(default), cbc, ctr]" << endl
			 <<	"-k - input file with key" << endl;
	}
	else if (help_mode == HelpMode::Pass) {
		cout <<	"-m pass (Cipher/Decipher mode with password based key)" << endl
			 << "-c - cipher mode [ecb(default), cbc, ctr]" << endl
			 << "-l - hash length [256, 512(default)]" << endl;
	}
}

void set_echo(bool on = true)
{
	DWORD  mode;
	HANDLE hConIn = GetStdHandle( STD_INPUT_HANDLE );
	GetConsoleMode( hConIn, &mode );
	mode = on
	   ? (mode |   ENABLE_ECHO_INPUT )
	   : (mode & ~(ENABLE_ECHO_INPUT));
	SetConsoleMode( hConIn, mode );
}

string request_password_from_user(bool confirm = true) {
   string password = "";
   string confirm_password = "";

   cout << "Enter password:" << endl;
   set_echo(false);

   char str[1024];
   do {
	   cin.getline(str, 1024);
	   password = string(str);
   } while(password.length() == 0);
   set_echo(true);

   if(!confirm)
	   return password;

   cout << "Confirm password:" << endl;
   set_echo(false);

   do {
	   cin.getline(str, 1024);
	   confirm_password = string(str);
   } while(confirm_password.length() == 0);
   set_echo(true);

   if (password != confirm_password) {
	   cout << "Password doesn't match. Cancel." << endl;
	   return "";
   }

   return password;
}

int check_args(std::map<char, char*> args) {
	auto mode_arg = args.find('m');
	auto help_arg = args.find('h');

	if (mode_arg != args.end()) {
		if (strcmp(mode_arg->second, "key") == 0) {
			if (help_arg != args.end()){
				print_help(Key);
				return -1;
			}
			else {
				auto c_arg = args.find('c');
				if (c_arg != args.end()
					&& strcmp(c_arg->second, "ecb") != 0
					&& strcmp(c_arg->second, "cbc") != 0
					&& strcmp(c_arg->second, "ctr") != 0) {
					print_help(Key, ((string)"Arg -c contains unknown value — ") + c_arg->second);
					return -1;
				}
			}
		} else if (strcmp(mode_arg->second, "pass") == 0) {
			if (help_arg != args.end()){
				print_help(Pass);
				return -1;
			}
			else {
				auto l_arg = args.find('l');
				if (l_arg != args.end()
					&& strcmp(l_arg->second, "512") != 0
					&& strcmp(l_arg->second, "256") != 0) {
					print_help(Pass, ((string)"Arg -l contains unknown value — ") + l_arg->second);
					return -1;
				}

				string password = request_password_from_user(args.find('r') == args.end());
				if (password.empty())
					return -1;
				args.insert(std::pair<char, char*>('p', &password[0]));
			}
		}
		else if (strcmp(mode_arg->second, "keygen") == 0) {
			if (help_arg != args.end()){
				print_help(Default);
				return -1;
			}
		}
		else {
			print_help(Default, ((string)"Arg -m contains unknown value — ") + mode_arg->second);
			return -1;
		}
	}
	else {
		print_help(Default, help_arg != args.end() ? "" : "Args doesn't contains required argument [-m]");
		return -1;
	}

	if (args.find('f') == args.end()) {
		print_help(Default, "Args doesn't contains required argument [-f]");
		return -1;
	}

	return 0;
}

Crypter* get_crypter(std::map<char, char*> args) {
	string mode = args.find('m')->second;

	KeyProvider* key_provider;
	if (mode == "key") {
		string file_path = args.find('f')->second;

		auto k_arg = args.find('k');
		string key_file_path = k_arg == args.end()
				? file_path + ".key" : k_arg->second;

		key_provider = new FileKeyProvider(key_file_path);
	} else if (mode == "pass") {
		string password = args.find('p')->second;
		auto l_arg = args.find('l');

		HashLength hash_length = l_arg == args.end()
				? HashLength::b512 : get_hash_length_from_str(l_arg->second);
		key_provider = new PassKeyProvider(password, hash_length);
	}

	auto c_arg = args.find('c');
	ChipherMode chipher_mode = c_arg == args.end()
			? ChipherMode::ECB : get_chipher_mode_from_str(c_arg->second);

	Crypter* crypter = new Crypter(key_provider, chipher_mode);
	return crypter;
}

void write_key_in_file(string key_file_path, vector<uint32_t> key) {
	ofstream out;

	out.open(key_file_path, std::ios_base::binary);

	for (size_t i = 0; i < key.size(); i++) {
		auto _key = key[i];
		out.write(reinterpret_cast<char*>(&_key), sizeof(_key));
	}

	out.close();

	cout << "Key has saved in - " + key_file_path << endl;
}

int main(int argc, char* argv[]) {
	std::map<char, char*> args;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			args.insert(std::pair<char, char*>(argv[i][1],
					(i + 1) >= argc || argv[i+1][0] == '-' ? (char*)"" : argv[i + 1]));
		}
	}

	if (check_args(args) == -1) {
		return 0;
	}

	string file_path = args.find('f')->second;
	string mode = args.find('m')->second;

	if (mode == "keygen") {
		vector<uint32_t> key = KeyGen256::gen_key();
		write_key_in_file(file_path, key);
	} else {
		Crypter* crypter = get_crypter(args);
		if (args.find('r') == args.end())
			crypter->encrypt_file(file_path);
		else
			crypter->decrypt_file(file_path);
	}

	cout << "Successfully done" << endl;
	return 0;
}
