#ifndef FILE_KEY_PROVIDER_H_
#define FILE_KEY_PROVIDER_H_


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
			throw std::domain_error("Can't open file — " + key_file_path);
		}

		uint32_t iter_key;
		while(in.read(reinterpret_cast<char*>(&iter_key), sizeof(iter_key))) {
			keys.push_back(iter_key);
		}

		in.close();

		if (keys.size() < 8)
			throw std::domain_error("invalid key — " + key_file_path);

		return keys;
	}
};


#endif /* FILE_KEY_PROVIDER_H_ */
