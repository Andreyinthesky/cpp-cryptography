#ifndef PASS_KEY_PROVIDER_H_
#define PASS_KEY_PROVIDER_H_


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


#endif /* PASS_KEY_PROVIDER_H_ */
