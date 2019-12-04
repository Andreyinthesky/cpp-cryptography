#ifndef KEYGEN_SIGNATURE_H_
#define KEYGEN_SIGNATURE_H_

#include "algorithms/gost_signature.h"

class KeyGenSignature {
	SignatureParams params = SignatureParamsSet::CryptoPro_A;
public:
	std::pair<Int<32>, ECPoint> generate_keys() {
		std::minstd_rand rnd(time(0));
		Int<32> secret_key = 0;
		while (secret_key <= 0 || secret_key >= params.q) {
			for (int i = 0; i < 8; i++) {
				secret_key.table[i] = (uint32_t)rnd();
			}
		}

		ECPoint P = ECPoint(params.p, params.a, params.b, params.x, params.y);
		ECPoint public_key = P * secret_key;

		return std::make_pair(secret_key, public_key);
	}
};



#endif /* KEYGEN_SIGNATURE_H_ */
