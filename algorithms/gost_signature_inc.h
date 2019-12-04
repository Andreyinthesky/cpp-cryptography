#ifndef ALGORITHMS_GOST_SIGNATURE_INC_H_
#define ALGORITHMS_GOST_SIGNATURE_INC_H_

#include "../ttmath/ttmathint.h"
#include "gost_stribog.h"
using ttmath::Int;

class ModMath {
private:
	static std::tuple<Int<512>, Int<512>, Int<512>>
		ext_euclidean_algorithm(Int<512> a, Int<512> b) {
		Int<512> s = 0;
		Int<512> old_s = 1;
		Int<512> t = 1;
		Int<512> old_t = 0;
		Int<512> r = b;
		Int<512> old_r = a;

		while (r != 0) {
			Int<512> quotient = old_r / r;

			Int<512> temp = r;
			r = old_r - quotient * r;
			old_r = temp;
			temp = s;
			s = old_s - quotient * s;
			old_s = temp;
			temp = t;
			t = old_t - quotient * t;
			old_t = temp;
		}

		return std::make_tuple(old_r, old_s, old_t);
	}

public:
	static Int<512> mul_inverse(Int<512> n, Int<512> p) {
		if (n < 0)
			return p - mul_inverse(-n, p);

		std::tuple<Int<512>, Int<512>, Int<512>> a =
				ext_euclidean_algorithm(n, p);
		Int<512> gcd = std::get<0>(a);
		Int<512> x = std::get<1>(a);
		Int<512> y = std::get<2>(a);

		if (gcd != 1)
			throw std::domain_error("has no multiplicative inverse");

//		if ((n * x) % p != 1) {
//			throw std::domain_error("f*ck");
//		}

		return mod(x, p);
	}

	//returns n (mod p)
	static Int<512> mod(Int<512> n, Int<512> p) {
		return n % p + (n < 0 ? p : 0);
	}

};

// Elliptic curve point
struct ECPoint {
public:
	Int<512> a; //params of elliptic curve
	Int<512> b;
	Int<512> x; //coords
	Int<512> y;
	Int<512> p; //module of elliptic curve

	static bool isZero(ECPoint p) {
		return p.x == 0 && p.y == 0;
	}

	ECPoint(Int<512> p, Int<512> a, Int<512> b, Int<512> x, Int<512> y) {
		this->p = p;
		this->a = a;
		this->b = b;
		this->x = x;
		this->y = y;
	}

	bool operator == (ECPoint other) {
		return this->x == other.x && this->y == other.y;
	}

	ECPoint operator + (ECPoint other) {
		ECPoint point = *this;

		if (isZero(point))
			return other;
		if (isZero(other))
			return point;

		if (point.x == other.x && point.y != other.y)
			return ECPoint(p, a, b, 0, 0);

		Int<512> m = point == other
				? (point.x * point.x * 3 + point.a) * ModMath::mul_inverse(point.y * 2, p)
				: (other.y - point.y) * ModMath::mul_inverse(other.x - point.x, p);

		Int<512> x = (m * m - point.x - other.x);
		Int<512> y = (m * (point.x - x) - point.y);

		return ECPoint(p, a, b, ModMath::mod(x, p), ModMath::mod(y, p));
	}

	ECPoint operator * (Int<512> n) {
		ECPoint result = ECPoint(p, a, b, 0, 0);
		ECPoint p = *this;

		while (n != 0) {
			if ((n & 0x01) == 1)
				result = result + p;

			p = p + p;
			n >>= 1;
		}

		return result;
	}

	friend std::ostream & operator<<(std::ostream & s, const ECPoint & point) {
		std::stringstream ss;
		ss << "(x: " << point.x << ", " << "y: " << point.y << ")";
		s << ss.str();
		return s;
	}
};


class SignatureParams {
public:
	Int<512> p; //prime number - mod of ellipse curve
	Int<512> a; //params of ellipse curve
	Int<512> b;
	Int<512> q; //q = m/n, n c N && (2^254 < q < 2^256 || 2^508 < q < 2^512)
	Int<512> x; //coords of base point
	Int<512> y;

	SignatureParams(Int<512> p, Int<512> a, Int<512> b, Int<512> q, Int<512> x, Int<512> y) {
		this->p = p;
		this->a = a;
		this->b = b;
		this->q = q;
		this->x = x;
		this->y = y;
	}
};

struct SignatureParamsSet {
	static SignatureParams Test;
	static SignatureParams CryptoPro_A;
};

SignatureParams SignatureParamsSet::Test = {
	Int<512>("57896044618658097711785492504343953926634992332820282019728792003956564821041"),
	7,
	Int<512>("43308876546767276905765904595650931995942111794451039583252968842033849580414"),
	Int<512>("57896044618658097711785492504343953927082934583725450622380973592137631069619"),
	2,
	Int<512>("4018974056539037503335449422937059775635739389905545080690979365213431566280")
};
SignatureParams SignatureParamsSet::CryptoPro_A = {
	(Int<512>)uint512_t(vector<uint32_t> {
		0xFFFFFD97, 0xFFFFFFFF, 0xFFFFFFFF,  0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
	}),
	(Int<512>)uint512_t(vector<uint32_t> {
		0xFFFFFD94, 0xFFFFFFFF, 0xFFFFFFFF,  0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
	}),
	166,
	(Int<512>)uint512_t(vector<uint32_t> {
		 0xB761B893, 0x45841B09, 0x995AD100, 0x6C611070, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	}),
	1,
	(Int<512>)uint512_t(vector<uint32_t> {
		0x9E9F1E14, 0x22ACC99C, 0xDF23E3B1, 0x35294F2D, 0x453F2B76, 0x27DF505A, 0xE0989CDA, 0x8D91E471,
	})
};

#endif /* ALGORITHMS_GOST_SIGNATURE_INC_H_ */
