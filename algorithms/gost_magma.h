#ifndef GOST_MAGMA_H_
#define GOST_MAGMA_H_

#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <ctime>

using std::cout;
using std::cin;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::vector;
using std::string;


const int ITER_COUNT = 32; // Block_length = 32 bit, Key_length = 64 bit
const uint8_t Pi[8][16] =
{
  {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1},
  {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
  {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
  {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
  {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
  {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
  {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
  {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2},
};

uint64_t g_map(uint64_t R, uint64_t key);
uint32_t t_map(uint32_t a);
uint64_t encrypt(uint64_t block, vector<uint32_t> keys);
uint64_t decrypt(uint64_t block, vector<uint32_t> keys);

#endif /* GOST_MAGMA_H_ */
