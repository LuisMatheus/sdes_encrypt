#pragma once
#include <bitset>
#include <vector>

using namespace std;

class sdesData {
public:
	vector<bitset<8>*> msg_En;
	bitset<10>* key;
};