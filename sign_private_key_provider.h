#ifndef SIGN_PRIVATE_KEY_PROVIDER_H_
#define SIGN_PRIVATE_KEY_PROVIDER_H_


#include "file_key_provider.h"
#include "algorithms/gost_signature_inc.h"

class SignaturePrivateKeyProvider {
private:
	FileKeyProvider* file_key_provider;

public:
	SignaturePrivateKeyProvider(FileKeyProvider* file_key_provider) {
		this->file_key_provider = file_key_provider;
	}

	Int<512> get_key() {
		vector<uint32_t> vec_key = file_key_provider->get_key();

		Int<512> key = 0;
		size_t vec_size = vec_key.size();
		for (int i = vec_size - 1; i >= 0; i--) {
			key.table[i] = vec_key[vec_size - i - 1];
		}

		return key;
	}
};



#endif /* SIGN_PRIVATE_KEY_PROVIDER_H_ */
