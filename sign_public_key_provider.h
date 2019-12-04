#ifndef SIGN_PUBLIC_KEY_PROVIDER_H_
#define SIGN_PUBLIC_KEY_PROVIDER_H_

#include "file_key_provider.h"
#include "algorithms/gost_signature_inc.h"

class SignaturePublicKeyProvider {
private:
	FileKeyProvider* file_key_provider;

public:
	SignaturePublicKeyProvider(FileKeyProvider* file_key_provider) {
		this->file_key_provider = file_key_provider;
	}

	ECPoint get_key() {
		vector<uint32_t> key = file_key_provider->get_key();

		if (key.size() < 32)
			throw std::domain_error("invalid public key — " + file_key_provider->key_file_path);

		Int<512> x = 0;
		Int<512> y = 0;

		SignatureParams curve_params = SignatureParamsSet::CryptoPro_A;

		for (int i = 0; i < 16; i++) {
			x.table[15 - i] = key[i];
		}

		for (int i = 16; i < 32; i++) {
			y.table[31 - i] = key[i];
		}

		return ECPoint(curve_params.p, curve_params.a, curve_params.b, x, y);
	}
};

#endif /* SIGN_PUBLIC_KEY_PROVIDER_H_ */
