#ifndef ALGORITHMS_GOST_SIGNATURE_H_
#define ALGORITHMS_GOST_SIGNATURE_H_

#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <ctime>
#include <tuple>

#include "gost_signature_inc.h"
#include "gost_stribog.h"
#include "../ttmath/ttmathint.h"
#include "../sign_public_key_provider.h"
#include "../sign_private_key_provider.h"

using ttmath::Int;

using std::cout;
using std::cin;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::vector;
using std::string;

class SignatureProcessor {
//uncomment for testing SignatureProcessor
//#define TEST_SIGNATURE

private:
	static const int SignatureSize = 512; // signature size in bits
	static const HashLength hash_len = HashLength::b256;

	#ifdef TEST_SIGNATURE
		SignatureParams params = SignatureParamsSet::Test;
	#endif

	#ifndef TEST_SIGNATURE
		SignatureParams params = SignatureParamsSet::CryptoPro_A;
	#endif

	static vector<uint32_t> make_signature(Int<32> r, Int<32> s) {
		vector<uint32_t> sign_vec;

		int startPos = SignatureSize / (2 * 8 * sizeof(uint32_t)) - 1;
		for (int i = startPos; i >= 0; i--) {
			uint32_t num_part = r.table[i];
			sign_vec.push_back(num_part);
		}

		for (int i = startPos; i >= 0; i--) {
			uint32_t num_part = s.table[i];
			sign_vec.push_back(num_part);
		}

		return sign_vec;
	}

	static std::pair<Int<32>, Int<32>> get_r_s(vector<uint32_t> signature) {
		Int<32> r = 0;
		Int<32> s = 0;

		int pointer = 0;
		int blocks_count = SignatureSize / (8 * sizeof(uint32_t));
		int startPos = blocks_count / 2 - 1;
		for (int i = startPos; i >= 0; i--) {
			uint32_t num_part = signature[pointer++];
			r.table[i] = num_part;
		}

		for (int i = startPos; i >= 0; i--) {
			uint32_t num_part = signature[pointer++];
			s.table[i] = num_part;
		}

		return std::make_pair(r, s);
	}

public:
	vector<uint32_t> generate(vector<uint8_t> msg, SignaturePrivateKeyProvider* signature_key_provider) {
		Int<512> key = signature_key_provider->get_key();

		return generate(msg, key);
	}

	vector<uint32_t> generate(vector<uint8_t> msg, Int<512> signature_key) {
		std::minstd_rand rnd(time(0));
		Int<512> k = 0;
		Int<512> e;
		Int<512> r;
		Int<512> s;
		ECPoint P = ECPoint(params.p, params.a, params.b, params.x, params.y);

#ifdef TEST_SIGNATURE
		cout << "Test Generate" << endl;
		signature_key = Int<512>("55441196065363246126355624130324183196576709222340016572108097750006097525544");
		e = Int<512>("20798893674476452017134061561508270130637142515379653289952617252661468872421");
		k = Int<512>("53854137677348463731403841147996619241504003434302020712960838528893196233395");

		cout << "q: " << params.q << endl;
		cout << "kP = " << k << " * " << P << endl;
		ECPoint c = P * k;
		cout << "x_C:" << c.x << endl;
		cout << "y_C:" << c.y << endl;

		r = ModMath::mod(c.x, params.q);
		cout << "r:" << r << endl;
		s = ModMath::mod(r * signature_key + k * e, params.q);
		cout << "s:" << s << endl;
#endif

#ifndef TEST_SIGNATURE
		Int<512> hash = get_hash((uint8_t*)&msg[0], msg.size() * 8, hash_len);
		e  = ModMath::mod(hash, params.q);
		e = e == 0 ? 1 : e;

		do {
			do {
				while (k <= 0 || k >= params.q) {
					for (size_t i = 0; i < SignatureSize / (2 * 8 * sizeof(uint32_t)); i++)
						k.table[i] = (uint32_t)rnd();
				}
				ECPoint C = P * k;
				r = ModMath::mod(C.x, params.q);
			} while (r == 0);
			s = ModMath::mod(r * signature_key + k * e, params.q);
		} while (s == 0);
#endif

		return make_signature(r, s);
	}

	bool verify(vector<uint8_t> msg, vector<uint32_t> signature, SignaturePublicKeyProvider* pbkey_provider) {
		ECPoint verify_key = pbkey_provider->get_key();

		return verify(msg, signature, verify_key);
	}

	bool verify(vector<uint8_t> msg, vector<uint32_t> signature, ECPoint verify_key) {
		std::pair<Int<32>, Int<32>> r_s = get_r_s(signature);

		Int<32> r = r_s.first;
		Int<32> s = r_s.second;

#ifdef TEST_SIGNATURE
		cout << "Test Verify" << endl;
		cout << "r: " << r << endl;
		cout << "s: " << s << endl;
		Int<32> e = Int<32>("20798893674476452017134061561508270130637142515379653289952617252661468872421");
		Int<32> x_Q = Int<32>("57520216126176808443631405023338071176630104906313632182896741342206604859403");
		Int<32> y_Q = Int<32>("17614944419213781543809391949654080031942662045363639260709847859438286763994");
		verify_key = ECPoint(params.p, params.a, params.b, x_Q, y_Q);
#endif

		if (r < 0 || r >= params.q || s < 0 || s >= params.q)
			return false;


#ifndef TEST_SIGNATURE
		Int<512> hash = (Int<512>)get_hash((uint8_t*)&msg[0], msg.size() * 8, hash_len);
		Int<512> e = ModMath::mod(hash, params.q);
#endif
		e = e == 0 ? 1 : e;

		Int<512> v = ModMath::mul_inverse(e, params.q);

		Int<512> z1 = ModMath::mod(s * v, params.q);
		Int<512> z2 = ModMath::mod(-r * v, params.q);

		ECPoint P = ECPoint(params.p, params.a, params.b, params.x, params.y);
		ECPoint C = P * z1 + verify_key * z2;
		Int<512> R = ModMath::mod(C.x, params.q);

#ifdef TEST_SIGNATURE
		cout << "v: " << v << endl;
		cout << "z1: " << z1 << endl;
		cout << "z2: " << z2 << endl;
		cout << "x_C: " << C.x << endl;
		cout << "y_C: " << C.y << endl;
		cout << "R: " << R << endl;
#endif

		return R == r;
	}
};

#endif /* ALGORITHMS_GOST_SIGNATURE_H_ */
