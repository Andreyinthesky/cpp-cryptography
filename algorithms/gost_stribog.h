#ifndef ALGORITHMS_GOST_STRIBOG_H_
#define ALGORITHMS_GOST_STRIBOG_H_

#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <ctime>
#include "../ttmath/ttmathint.h"

using std::cout;
using std::cin;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::vector;
using std::string;

enum HashLength {
	b256 = 0,
	b512 = 1,
};

const uint8_t Pi_stribog[] = {
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
	153, 186, 23, 54, 241,187, 20, 205, 95, 193, 249, 24, 101,90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142,
	79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11,237, 152, 127, 212, 211, 31,235, 52, 44, 81,234, 200, 72, 171,
	242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71,156, 183, 93, 135, 21,
	161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126,
	109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201,215, 121,214, 246, 124, 34, 185, 3,
	224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26,
	184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88,
	179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225,27, 131,73, 76, 63, 248, 254, 141,83,
	170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
	116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
};

const int Tau[] = {
	0, 8, 16, 24, 32, 40, 48, 56,
	1, 9, 17, 25, 33, 41, 49, 57,
	2, 10, 18, 26, 34, 42, 50, 58,
	3, 11, 19, 27, 35, 43, 51, 59,
	4, 12, 20, 28, 36, 44, 52, 60,
	5, 13, 21, 29, 37, 45, 53, 61,
	6, 14, 22, 30, 38, 46, 54, 62,
	7, 15, 23, 31, 39, 47, 55, 63
};

const uint64_t A[] = {
	0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
	0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
	0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
	0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
	0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
	0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
	0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
	0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
	0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
	0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
	0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
	0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
	0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
	0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
	0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
	0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
};

const vector<uint64_t> C[] = {
	{0xdd806559f2a64507, 0x05767436cc744d23, 0xa2422a08a460d315, 0x4b7ce09192676901, 0x714eb88d7585c4fc, 0x2f6a76432e45d016, 0xebcb2f81c0657c1f, 0xb1085bda1ecadae9, },
	{0xe679047021b19bb7, 0x55dda21bd7cbcd56, 0x5cb561c2db0aa7ca, 0x9ab5176b12d69958, 0x61d55e0f16b50131, 0xf3feea720a232b98, 0x4fe39d460f70b5d7, 0x6fa3b58aa99d2f1a, },
	{0x991e96f50aba0ab2, 0xc2b6f443867adb31, 0xc1c93a376062db09, 0xd3e20fe490359eb1, 0xf2ea7514b1297b7b, 0x06f15e5f529c1f8b, 0x0a39fc286a3d8435, 0xf574dcac2bce2fc7, },
	{0x220cbebc84e3d12e, 0x3453eaa193e837f1, 0xd8b71333935203be, 0xa9d72c82ed03d675, 0x9d721cad685e353f, 0x488e857e335c3c7d, 0xf948e1a05d71e4dd, 0xef1fdfb3e81566d2, },
	{0x601758fd7c6cfe57, 0x7a56a27ea9ea63f5, 0xdfff00b723271a16, 0xbfcd1747253af5a3, 0x359e35d7800fffbd, 0x7f151c1f1686104a, 0x9a3f410c6ca92363, 0x4bea6bacad474799, },
	{0xfa68407a46647d6e, 0xbf71c57236904f35, 0x0af21f66c2bec6b6, 0xcffaa6b71c9ab7b4, 0x187f9ab49af08ec6, 0x2d66c4f95142a46c, 0x6fa4c33b7a3039c0, 0xae4faeae1d3ad3d9, },
	{0x8886564d3a14d493, 0x3517454ca23c4af3, 0x06476983284a0504, 0x0992abc52d822c37, 0xd3473e33197a93c9, 0x399ec6c7e6bf87c9, 0x51ac86febf240954, 0xf4c70e16eeaac5ec, },
	{0xa47f0dd4bf02e71e, 0x36acc2355951a8d9, 0x69d18d2bd1a5c42f, 0xf4892bcb929b0690, 0x89b4443b4ddbc49a, 0x4eb7f8719c36de1e, 0x03e7aa020c6e4141, 0x9b1f5b424d93c9a7, },
	{0x7261445183235adb, 0x0e38dc92cb1f2a60, 0x7b2b8a9aa6079c54, 0x800a440bdbb2ceb1, 0x3cd955b7e00d0984, 0x3a7d3a1b25894224, 0x944c9ad8ec165fde, 0x378f5a541631229b, },
	{0x74b4c7fb98459ced, 0x3698fad1153bb6c3, 0x7a1e6c303b7652f4, 0x9fe76702af69334b, 0x1fffe18a1b336103, 0x8941e71cff8a78db, 0x382ae548b2e4f3f3, 0xabbedea680056f52, },
	{0x6bcaa4cd81f32d1b, 0xdea2594ac06fd85d, 0xefbacd1d7d476e98, 0x8a1d71efea48b9ca, 0x2001802114846679, 0xd8fa6bbbebab0761, 0x3002c6cd635afe94, 0x7bcd9ed0efc889fb, },
	{0x48bc924af11bd720, 0xfaf417d5d9b21b99, 0xe71da4aa88e12852, 0x5d80ef9d1891cc86, 0xf82012d430219f9b, 0xcda43c32bcdf1d77, 0xd21380b00449b17a, 0x378ee767f11631ba, },
};



struct uint512_t {
private:
	vector<uint32_t> bits;

	std::pair<uint512_t, uint512_t> division(uint512_t a, uint512_t b) {
		if (b == 0) throw "divide by zero";

		uint512_t z = 1;
		uint512_t tempB = b;
		int k = 0;

		while (a >= b) {
			b = b << 1;

			if (b < tempB) {
				b = tempB;
				break;
			}

			tempB = b;
			z = z << 1;
			k++;
		}

		uint512_t div = 0;

		while (k > 0) {
			b = b >> 1;
			z = z >> 1;
			k--;
			if (a >= b) {
				a = a - b;
				div = div + z;
			}
		}

		return std::make_pair(div, a);
	}

public:
	uint512_t() {
		for (int i = 0; i < 16; i++) {
			bits.push_back(0);
		}
	}

	uint512_t(uint32_t number) {
		bits.push_back(number);
		for (int i = 0; i < 15; i++) {
			bits.push_back(0);
		}
	}

	uint512_t(vector<uint32_t> bits) {
		for (int i = 0; i < 16; i++) {
			this->bits.push_back(0);
		}

		for (size_t i = 0; i < bits.size() && i < 16; i++) {
			this->bits[i] = bits[i];
		}
	}

	uint512_t(vector<uint64_t> bits) {
		for (int i = 0; i < 16; i++) {
			this->bits.push_back(0);
		}

		for (size_t i = 0; i < bits.size() && i < 8; i++) {
			uint32_t right = bits[i] & 0xffffffff;
			uint32_t left = bits[i] >> 32;
			this->bits[2 * i] = right;
			this->bits[2 * i + 1] = left;
		}
	}

	size_t size() {
		return bits.size();
	}

	bool operator ==(uint32_t number) {
		for (size_t i = 1; i < bits.size(); i++) {
			if (bits[i] != 0) return false;
		}

		return bits[0] == number;
	}

	bool operator ==(uint512_t other) {
		for (size_t i = 0; i < bits.size(); i++) {
			if (other[i] != bits[i]) return false;
		}

		return true;
	}

	bool operator <(uint512_t other) {
		for (int i = bits.size() - 1; i >= 0; i--) {
			if (bits[i] < other[i]) return true;
			else if (bits[i] > other[i]) return false;
		}

		return false;
	}

	bool operator !=(uint512_t other) {
		return !(*this == other);
	}

	bool operator <=(uint512_t other) {
		return (*this < other || *this == other);
	}

	bool operator >(uint512_t other) {
		return !(*this <= other);
	}

	bool operator >=(uint512_t other) {
		return !(*this < other);
	}

	uint512_t operator *(uint512_t other) {
		uint512_t res = 0;

		for (size_t i = 0; i < bits.size(); i++) {
			uint32_t carry = 0;
			for (size_t j = 0; j < other.size() && (i + j) < bits.size(); j++) {
				uint64_t temp = (uint64_t)((*this)[i]) * other[j] + carry;
				uint64_t res_temp = temp + res[i + j];
				carry = (res_temp >> 32);
				res[i + j] = res_temp & 0xffffffff;
			}
		}

		return res;
	}

	uint512_t operator *(uint32_t n) {
		uint512_t other = n;

		return (*this) * other;
	}

	uint512_t operator /(uint512_t other) {
		return division(*this, other).first;
	}

	uint512_t operator %(uint512_t other) {
		return division(*this, other).second;
	}

	uint32_t& operator [](const int block_index) {
		return this->bits[block_index];
	}

	uint512_t operator ^(uint512_t other) {
		vector<uint32_t> result;

		for (size_t i = 0; i < bits.size(); i++) {
			result.push_back(this->bits[i] ^ other[i]);
		}

		return uint512_t(result);
	}

	uint512_t operator~() {
		uint512_t result = 0;

		for (size_t i = 0; i < result.size(); i++) {
			result[i] = ~(this->bits[i]);
		}

		return result;
	}

	uint512_t operator >>(uint32_t n) {
		uint512_t res;

		if (n > 511) return res;

		int k = n / 32;
		int l = n % 32;

		uint32_t carry = 0;
		for (int i = bits.size() - 1; i >= k; i--) {
			uint64_t temp = ((uint64_t)bits[i]) << (32 - l);
			res[i - k] = carry + (temp >> 32);
			carry = temp & 0xffffffff;
		}

		return res;
	}

	uint512_t operator <<(uint32_t n) {
		uint512_t res;

		if (n > 511) return res;

		uint32_t k = n / 32;
		uint32_t l = n % 32;

		uint32_t carry = 0;
		for (size_t i = k; i < bits.size(); i++) {
			uint64_t temp = ((uint64_t)bits[i - k]) << l;
			res[i] = carry + (temp & 0xffffffff);
			carry = (temp >> 32);
		}

		return res;
	}

	uint512_t operator +(uint512_t other) {
		vector<uint32_t> result;

		uint64_t temp = 0;
		for (size_t i = 0; i < bits.size(); i++) {
			temp = (uint64_t)bits[i] + other[i] + (temp >> 32);
			result.push_back(temp & 0xffffffff);
		}

		return uint512_t(result);
	}

	uint512_t operator +(uint64_t number) {
		uint512_t other;

		other.bits[0] = number & 0xffffffff;
		other.bits[1] = number >> 32;

		return *this + other;
	}

	uint512_t operator -(uint512_t other) {
		other = (~other) + 1;

		return *this + other;
	}

	explicit operator string() {
		char bytes[64];

		for (int i = bits.size() - 1; i >= 0; i--) {
			for (int j = 0; j < 4; j++) {
				bytes[4 * i + j] = (bits[i] >> (3 - j)) & 0xff;
			}
		}

		return string(bytes);
	}

	operator ttmath::Int<512>() {
		ttmath::Int<512> res = 0;

		for (size_t i = 0; i < size(); i++) {
			res.table[i] = bits[i];
		}

		return res;
	}

	static void print(uint512_t n) {
		for (int i = n.size() - 1; i >= 0; i--)
			printf("%08x", n[i]);
		printf("\n");
	}
};


uint512_t X_map(uint512_t k, uint512_t a);
uint512_t S_map(uint512_t block);
uint512_t P_map(uint512_t block);
uint512_t L_map(uint512_t block);
uint512_t E_map(uint512_t K, uint512_t m);
vector<uint512_t> get_keys(uint512_t K);
uint8_t* complete_msg(uint8_t* msg, uint64_t msg_len_in_bits);
uint512_t compress(uint512_t N, uint512_t h, uint512_t m);
uint512_t get_hash(uint8_t* msg, uint64_t msg_len_in_bits, HashLength hash_len = HashLength::b512);

#endif /* ALGORITHMS_GOST_STRIBOG_H_ */
