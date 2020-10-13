#pragma once
#include <iostream>
#include <bitset>
#include <algorithm>
#include <vector>
#include <string>
#include <cstdlib>
#include <time.h> 

#include "sdesData.h"

using namespace std;

class SDES {
public:
	sdesData* encrypt(string message);

	string decrypt(sdesData* data);
private:

	const int s0[4][4] = { {1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2} };
	const int s1[4][4] = { {0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3} };

	vector<bitset<8>> getKeys(bitset<10> key_enc);
};