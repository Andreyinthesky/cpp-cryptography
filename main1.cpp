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
#include "crypter.h"
#include "key_provider.h"
#include "keygen_256.h"
#include "keygen_signature.h"
#include "file_key_provider.h"
#include "pass_key_provider.h"
#include "main.h"

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

void print_help(HelpMode help_mode = HelpMode::Default, string msg = "") {
	if (!msg.empty())
		cout << msg << endl;

	switch(help_mode) {
		case HelpMode::Default :
			cout << "-m - mode [keygen, key, pass, sign] {Required}" << endl
				 << "-h - help" << endl;
			break;
		case HelpMode::Key :
			cout <<	"-m key (Cipher/Decipher mode with key located in file)" << endl
				 <<	"-r - decipher mode" << endl
				 << "-c - cipher mode [ecb(default), cbc, ctr]" << endl
				 <<	"-k - input file with key" << endl
				 << "-f - input file for enciphering {Required}" << endl;
			break;
		case HelpMode::Pass :
			cout <<	"-m pass (Cipher/Decipher mode with password based key)" << endl
				 <<	"-r - decipher mode" << endl
				 << "-c - cipher mode [ecb(default), cbc, ctr]" << endl
				 << "-l - hash length [256, 512(default)]" << endl
				 << "-f - input file for enciphering {Required}" << endl;
			break;
		case HelpMode::KeyGen :
			cout <<	"-m keygen (256 bit key generator)" << endl
				 << "-n - key name {Required}" << endl
				 << "-g - generation type [single(default), signature]" << endl
				 << "	single - generates private key" << endl
				 << "	signature - generates private-public key pair special for signature processing" << endl;
			break;
		case HelpMode::Sign :
			cout <<	"-m sign (Processing signature)" << endl
				 << "-k - input file with key {Required}" << endl
				 <<	"-v - verify signature mode" << endl
				 << "-s - input file with signature {Required if -v active}" << endl
				 << "-f - path to file for processing signature {Required}" << endl;
			break;
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
   char str[1024];

   cout << "Enter password:" << endl;
   set_echo(false);

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

	if (mode_arg == args.end()) {
		print_help(Default, help_arg != args.end() ? "" : "Args doesn't contains required argument [-m]");
		return -1;
	}

	string mode_arg_str = string(mode_arg->second);

	if (mode_arg_str == "key") {
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
	}
	else if (mode_arg_str == "pass") {
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
	else if (mode_arg_str == "keygen") {
		if (help_arg != args.end()) {
			print_help(KeyGen);
			return -1;
		}

		auto name_arg = args.find('n');
		auto g_arg = args.find('g');
		if (name_arg == args.end()) {
			print_help(KeyGen, "Arg -n is required");
			return -1;
		}

		if (g_arg != args.end()){
			string g_arg_str = string(g_arg->second);
			if (g_arg_str != "single" && g_arg_str != "signature") {
				print_help(KeyGen, ((string)"Arg -g contains unknown value — ") + g_arg_str);
				return -1;
			}
		}
	}
	else if (mode_arg_str == "sign") {
		if (help_arg != args.end()) {
			print_help(Sign);
			return -1;
		}

		auto v_arg = args.find('v');
		auto s_arg = args.find('s');
		auto k_arg = args.find('k');
		if (k_arg == args.end()) {
			print_help(Sign, "Arg -k is required");
			return -1;
		}

		if (v_arg != args.end() && s_arg == args.end()) {
			print_help(KeyGen, "Arg -s is required");
			return -1;
		}
	}
	else {
		print_help(Default, ((string)"Arg -m contains unknown value — ") + mode_arg->second);
		return -1;
	}

	if (args.find('f') == args.end() && mode_arg_str != "keygen") {
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

vector<uint8_t> read_data_from_file(string file_path) {
	ifstream in;

	in.open(file_path, std::ifstream::binary | std::ifstream::ate);

	if (!in.is_open()) {
		throw std::domain_error("Can't open file — " + file_path);
	}

	uint64_t file_size = in.tellg();

	if (file_size == 0)
		throw std::domain_error("Empty file — " + file_path);

	in.seekg(0);
	vector<uint8_t> vector;

	uint8_t temp = 0;
	while(in.read(reinterpret_cast<char*>(&temp), sizeof(temp)))
		vector.push_back(temp);

	in.close();

	return vector;
}

void write_signature(string sign_name, vector<uint32_t> signature){
	write_data_in_file(sign_name + ".sign", signature);
	cout << "Signature has saved in - " + sign_name + ".sign" << endl;
}

void write_single_key(string key_name, vector<uint32_t> key){
	write_data_in_file(key_name + ".key", key);
	cout << "Key has saved in - " + key_name + ".key" << endl;
}

void write_pair_keys(string key_name, std::pair<Int<32>, ECPoint> pair) {
	Int<32> private_key = pair.first;
	ECPoint public_key = pair.second;
	vector<uint32_t> data;

	for (int i = 15; i >= 0; i--)
		data.push_back(private_key.table[i]);

	write_data_in_file(key_name + ".prkey", data);
	cout << "Private key has saved in - " + key_name + ".prkey" << endl;
	data = vector<uint32_t>();

	for (int i = 15; i >= 0; i--)
		data.push_back(public_key.x.table[i]);

	for (int i = 15; i >= 0; i--)
		data.push_back(public_key.y.table[i]);

	write_data_in_file(key_name + ".pubkey", data);
	cout << "Public key has saved in - " + key_name + ".pubkey" << endl;
}

void write_data_in_file(string file_path, vector<uint32_t> data) {
	ofstream out;

	out.open(file_path, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);

	for (size_t i = 0; i < data.size(); i++) {
		uint32_t _key = data[i];
		out.write(reinterpret_cast<char*>(&_key), sizeof(_key));
	}

	out.close();
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

	string file_path =  args.find('f') == args.end() ? "" : args.find('f')->second;
	string mode = args.find('m')->second;

	if (mode == "keygen") {
		string gen_type = args.find('g') == args.end() ? "" : args.find('g')->second;
		string key_name = args.find('n')->second;

		if (gen_type.empty() || gen_type == "single") {
			vector<uint32_t> key = KeyGen256::gen_key();
			write_single_key(key_name, key);
		} else if (gen_type == "signature") {
			KeyGenSignature key_gen;
			auto keys = key_gen.generate_keys();
			write_pair_keys(key_name, keys);
		}
	}
	else if (mode == "sign") {
		SignatureProcessor proc;
		string key_file_path = args.find('k')->second;
		vector<uint8_t> msg = read_data_from_file(file_path);

		if (args.find('v') != args.end()) {
			string signature_file_path = args.find('s')->second;
			vector<uint32_t> signature = FileKeyProvider(signature_file_path).get_key();

			cout << "Start verifying" << endl;
			bool verdict =
					proc.verify(msg, signature, new SignaturePublicKeyProvider(new FileKeyProvider(key_file_path)));

			cout << (verdict ? "Accept" : "Decline") << " " << "signature" << endl;
		}
		else {
			cout << "Start signature generation" << endl;
			vector<uint32_t> signature =
					proc.generate(msg, new SignaturePrivateKeyProvider(new FileKeyProvider(key_file_path)));
			write_signature(file_path, signature);
		}
	}
	else {
		Crypter* crypter = get_crypter(args);
		if (args.find('r') == args.end())
			crypter->encrypt_file(file_path);
		else
			crypter->decrypt_file(file_path);
	}

	cout << "Successfully done" << endl;
	return 0;
}
