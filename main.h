#ifndef MAIN_H_
#define MAIN_H_


enum ChipherMode {
	ECB = 0,
	CBC,
	CTR
};

enum HelpMode {
	Default,
	KeyGen,
	Key,
	Pass,
	Sign,
};

vector<uint8_t> read_data_from_file(string file_path);
void write_data_in_file(string file_path, vector<uint32_t> data);

#endif /* MAIN_H_ */
