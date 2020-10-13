#include "SDES.h"

sdesData* SDES::encrypt(string message)
{
	sdesData* data = new sdesData();

	//chave aleatoria
	//srand(time(NULL));
	data->key = new bitset<10>(rand() % 1024);

	vector<bitset<8>> keys = getKeys(*data->key);

	bitset<2> linha_s0 ,col_s0, linha_s1,col_s1,s0_res,s1_res;
	bitset<4> p4 , res_xor_1;
	bitset<8> msg, ip, ep ,res_xor, ext, ext_1;

	string aux;

	for (char c : message) {
		aux = "";
		aux = bitset<8>(c).to_string();
		for (int i = 0 ; i < 8 ; i++)
		{
			if (aux.at(i) == '1')  {
				msg[i] = 1;
			}
			else{
				msg[i] = 0;
			}

		}

		//permutacao
		ip[0] = msg[1];
		ip[1] = msg[5];
		ip[2] = msg[2];
		ip[3] = msg[0];
		//-------------
		ip[4] = msg[3];
		ip[5] = msg[7];
		ip[6] = msg[4];
		ip[7] = msg[6];

		//EP
		ep[0] = ip[7];
		ep[1] = ip[4];
		ep[2] = ip[5];
		ep[3] = ip[6];
		ep[4] = ip[5];
		ep[5] = ip[6];
		ep[6] = ip[7];
		ep[7] = ip[4];

		//ou exclusivo
		for (int i = 0; i < 8; i++) {
			res_xor[i] = ep[i] ^ keys.at(0)[i];
		}

		//s0
		//linha

		linha_s0.set(0, res_xor[0]);
		linha_s0.set(1, res_xor[3]);

		//col

		col_s0.set(0, res_xor[1]);
		col_s0.set(1, res_xor[2]);

		//s1
		//linha

		linha_s1.set(0, res_xor[4]);
		linha_s1.set(1, res_xor[7]);

		//col

		col_s1.set(0, res_xor[5]);
		col_s1.set(1, res_xor[6]);

		s0_res = s0[linha_s0.to_ulong()][col_s0.to_ulong()];
		s1_res = s1[linha_s1.to_ulong()][col_s1.to_ulong()];

		//p4

		p4[0] = s0_res[1];
		p4[1] = s1_res[1];
		p4[2] = s1_res[0];
		p4[3] = s0_res[0];

		//ou exclusivo
		for (int i = 0; i < 4; i++)
		{
			res_xor_1[i] = p4[i] ^ ip[i];
		}

		//saida 1 (invertida)

		ext[0] = ip[4];
		ext[1] = ip[5];
		ext[2] = ip[6];
		ext[3] = ip[7];
		//---------------------------
		ext[4] = res_xor_1[0];
		ext[5] = res_xor_1[1];
		ext[6] = res_xor_1[2];
		ext[7] = res_xor_1[3];

		//-----------------------------------------------------

		//EP
		ep[0] = ext[7];
		ep[1] = ext[4];
		ep[2] = ext[5];
		ep[3] = ext[6];
		ep[4] = ext[5];
		ep[5] = ext[6];
		ep[6] = ext[7];
		ep[7] = ext[4];

		//ou exclusivo
		for (int i = 0; i < 8; i++) {
			res_xor[i] = ep[i] ^ keys.at(1)[i];
		}

		//s0
		//linha
		linha_s0.set(0, res_xor[0]);
		linha_s0.set(1, res_xor[3]);

		//col
		col_s0.set(0, res_xor[1]);
		col_s0.set(1, res_xor[2]);

		//s1
		//linha
		linha_s1.set(0, res_xor[4]);
		linha_s1.set(1, res_xor[7]);

		//col
		col_s1.set(0, res_xor[5]);
		col_s1.set(1, res_xor[6]);

		s0_res = s0[linha_s0.to_ulong()][col_s0.to_ulong()];
		s1_res = s1[linha_s1.to_ulong()][col_s1.to_ulong()];

		//p4
		p4[0] = s0_res[1];
		p4[1] = s1_res[1];
		p4[2] = s1_res[0];
		p4[3] = s0_res[0];

		//ou exclusivo
		for (int i = 0; i < 4; i++)
		{
			res_xor_1[i] = p4[i] ^ ext[i];
		}

		//saida ip-1
		ext_1[0] = res_xor_1[3];
		ext_1[1] = res_xor_1[0];
		ext_1[2] = res_xor_1[2];
		ext_1[3] = ext[4];
		ext_1[4] = ext[6];
		ext_1[5] = res_xor_1[1];
		ext_1[6] = ext[7];
		ext_1[7] = ext[5];

		data->msg_En.push_back(new bitset<8>(ext_1));
	}

	return data;
}

string SDES::decrypt(sdesData* data)
{
	vector<bitset<8>> keys = getKeys(*data->key);


	bitset<2> linha_s0, col_s0, linha_s1, col_s1, s0_res, s1_res;
	bitset<4> p4, res_xor_1;
	bitset<8> msg, ip, ep, res_xor, ext, ext_1;

	string s = "", aux, aux1;

	for (bitset<8>* dta : data->msg_En)
	{
		msg = *dta;

		//permutacao
		ip[0] = msg[1];
		ip[1] = msg[5];
		ip[2] = msg[2];
		ip[3] = msg[0];
		//-------------
		ip[4] = msg[3];
		ip[5] = msg[7];
		ip[6] = msg[4];
		ip[7] = msg[6];

		//EP
		ep[0] = ip[7];
		ep[1] = ip[4];
		ep[2] = ip[5];
		ep[3] = ip[6];
		ep[4] = ip[5];
		ep[5] = ip[6];
		ep[6] = ip[7];
		ep[7] = ip[4];

		//ou exclusivo
		for (int i = 0; i < 8; i++) {
			res_xor[i] = ep[i] ^ keys.at(1)[i];
		}

		//s0
		//linha

		linha_s0.set(0, res_xor[0]);
		linha_s0.set(1, res_xor[3]);

		//col

		col_s0.set(0, res_xor[1]);
		col_s0.set(1, res_xor[2]);

		//s1
		//linha

		linha_s1.set(0, res_xor[4]);
		linha_s1.set(1, res_xor[7]);

		//col

		col_s1.set(0, res_xor[5]);
		col_s1.set(1, res_xor[6]);

		s0_res = s0[linha_s0.to_ulong()][col_s0.to_ulong()];
		s1_res = s1[linha_s1.to_ulong()][col_s1.to_ulong()];

		//p4

		p4[0] = s0_res[1];
		p4[1] = s1_res[1];
		p4[2] = s1_res[0];
		p4[3] = s0_res[0];

		//ou exclusivo
		for (int i = 0; i < 4; i++)
		{
			res_xor_1[i] = p4[i] ^ ip[i];
		}

		//saida 1 (invertida)

		ext[0] = ip[4];
		ext[1] = ip[5];
		ext[2] = ip[6];
		ext[3] = ip[7];
		//---------------------------
		ext[4] = res_xor_1[0];
		ext[5] = res_xor_1[1];
		ext[6] = res_xor_1[2];
		ext[7] = res_xor_1[3];

		//-----------------------------------------------------

		//EP
		ep[0] = ext[7];
		ep[1] = ext[4];
		ep[2] = ext[5];
		ep[3] = ext[6];
		ep[4] = ext[5];
		ep[5] = ext[6];
		ep[6] = ext[7];
		ep[7] = ext[4];

		//ou exclusivo
		for (int i = 0; i < 8; i++) {
			res_xor[i] = ep[i] ^ keys.at(0)[i];
		}

		//s0
		//linha
		linha_s0.set(0, res_xor[0]);
		linha_s0.set(1, res_xor[3]);

		//col
		col_s0.set(0, res_xor[1]);
		col_s0.set(1, res_xor[2]);

		//s1
		//linha
		linha_s1.set(0, res_xor[4]);
		linha_s1.set(1, res_xor[7]);

		//col
		col_s1.set(0, res_xor[5]);
		col_s1.set(1, res_xor[6]);

		s0_res = s0[linha_s0.to_ulong()][col_s0.to_ulong()];
		s1_res = s1[linha_s1.to_ulong()][col_s1.to_ulong()];

		//p4
		p4[0] = s0_res[1];
		p4[1] = s1_res[1];
		p4[2] = s1_res[0];
		p4[3] = s0_res[0];

		//ou exclusivo
		for (int i = 0; i < 4; i++)
		{
			res_xor_1[i] = p4[i] ^ ext[i];
		}

		//saida ip-1
		ext_1[0] = res_xor_1[3];
		ext_1[1] = res_xor_1[0];
		ext_1[2] = res_xor_1[2];
		ext_1[3] = ext[4];
		ext_1[4] = ext[6];
		ext_1[5] = res_xor_1[1];
		ext_1[6] = ext[7];
		ext_1[7] = ext[5];


		aux = string(ext_1.to_string());
		reverse(aux.begin(), aux.end());
		ext_1 = bitset<8>(aux);
		s = s + char(ext_1.to_ulong());
	}

	return s;
}

vector<bitset<8>> SDES::getKeys(bitset<10> key_enc)
{
	//criando p10
	bitset<10> p10;
	p10[0] = key_enc[2];
	p10[1] = key_enc[4];
	p10[2] = key_enc[1];
	p10[3] = key_enc[6];
	p10[4] = key_enc[3];
	p10[5] = key_enc[9];
	p10[6] = key_enc[0];
	p10[7] = key_enc[8];
	p10[8] = key_enc[7];
	p10[9] = key_enc[5];

	//criando ls1
	bitset<10> ls1;
	//shift esquerdo
	ls1[0] = p10[1];
	ls1[1] = p10[2];
	ls1[2] = p10[3];
	ls1[3] = p10[4];
	ls1[4] = p10[0];

	//shift direita
	ls1[5] = p10[6];
	ls1[6] = p10[7];
	ls1[7] = p10[8];
	ls1[8] = p10[9];
	ls1[9] = p10[5];

	//p8(k1)
	bitset<8> k1_p8;
	k1_p8[0] = ls1[5];
	k1_p8[1] = ls1[2];
	k1_p8[2] = ls1[6];
	k1_p8[3] = ls1[3];
	k1_p8[4] = ls1[7];
	k1_p8[5] = ls1[4];
	k1_p8[6] = ls1[9];
	k1_p8[7] = ls1[8];

	//criando ls2
	bitset<10> ls2;
	//shift esquerdo
	ls2[0] = ls1[2];
	ls2[1] = ls1[3];
	ls2[2] = ls1[4];
	ls2[3] = ls1[0];
	ls2[4] = ls1[1];

	//shift direita
	ls2[5] = ls1[7];
	ls2[6] = ls1[8];
	ls2[7] = ls1[9];
	ls2[8] = ls1[5];
	ls2[9] = ls1[6];

	//p8(k2)
	bitset<8> k2_p8;
	k2_p8[0] = ls2[5];
	k2_p8[1] = ls2[2];
	k2_p8[2] = ls2[6];
	k2_p8[3] = ls2[3];
	k2_p8[4] = ls2[7];
	k2_p8[5] = ls2[4];
	k2_p8[6] = ls2[9];
	k2_p8[7] = ls2[8];

	vector<bitset<8>> keys;
	keys.push_back(k1_p8);
	keys.push_back(k2_p8);

	return keys;
}
