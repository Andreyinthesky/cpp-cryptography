#ifndef KEY_PROVIDER_H_
#define KEY_PROVIDER_H_

class KeyProvider {
protected:
	KeyProvider() {}

public:
	virtual vector<uint32_t> get_key() = 0;
};



#endif /* KEY_PROVIDER_H_ */
