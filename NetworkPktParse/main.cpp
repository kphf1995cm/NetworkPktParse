
/*
 * func: parse network packet
 * name: peng kp18@mails.tsinghua.edu.cn
 * time: 2019-2-11
 */

#include<iostream>
#include<iomanip>
using namespace std;

struct Data {

	int av1;
	double ap1;
	int av2;
	double ap2;
	int av3;
	double ap3;
	int av4;
	double ap4;
	int av5;
	double ap5;

	int bv1;
	double bp1;
	int bv2;
	double bp2;
	int bv3;
	double bp3;
	int bv4;
	double bp4;
	int bv5;
	double bp5;

};

void init()
{
	Data data;
	data.av1 = 2122;
	data.ap1 = 1000.9;
	data.av2 = 33125;
	data.ap2 = 1100.8;
	data.av3 = 21343;
	data.ap3 = 1200.7;
	data.av4 = 1234;
	data.ap4 = 1260.2;
	data.av5 = 2099;
	data.ap5 = 1384.1;

	data.bv1 = 8821;
	data.bp1 = 990.5;
	data.bv2 = 7413;
	data.bp2 = 987.3;
	data.bv3 = 31123;
	data.bp3 = 960.9;
	data.bv4 = 8732;
	data.bp4 = 957.8;
	data.bv5 = 3130;
	data.bp5 = 924.1;
}

// a unit is 32 byte
int plaintext[] = {
	0x084a,0x0,0x33333333,0x408f4733,
	0x8165,0x0,0x33333333,0x40913333,
	0x535f,0x0,0xcccccccd,0x4092c2cc,
	0x04d2,0x0,0xcccccccd,0x4093b0cc,
	0x0833,0x7ffc,0x66666666,0x4095a066,
	0x2275,0x7ffc,0x0,0x408ef400,
	0x1cf5,0x0,0x66666666,0x408eda66,
	0x7993,0x0,0x33333333,0x408e0733,
	0x221c,0x0,0x66666666,0x408dee66,
	0x0c3a,0x7ffc,0xcccccccd,0x408ce0cc
};

int ciphertext[] = {
	0x0490,0x0,0xcdcdcdcd,0x25c1cd,
	0x7dab,0x0,0xcdcdcdcd,0x27adcd,
	0x4fa5,0x0,0x66666667,0x283c66,
	0x18,0x0,0x66666667,0x292a66,
	0x0479,0x7ffc,0x0,0x2b1a00,
	0x1ebb,0x7ffc,0x9a9a9a9a,0x246e9a,
	0x183b,0x0,0x0,0x245400,
	0x75d9,0x0,0xcdcdcdcd,0x2481cd,
	0x1e62,0x0,0x0,0x236800,
	0x0880,0x7ffc,0x66666667,0x225a66
};

// (0-4] byte 整体加密
// 4-8 byte 不加密
// 8-12 byte 字节加密
// 14-15 byte 单字节加密 106
// 15-16 byte 单字节加密 64
// 12-14 byte 双字节加密 16490
int packet[] = {
	0xa0e,0x0,0x33333334,0x27ad33,
	0x765b,0x0,0xcdcdcdcd,0x283dcd,
	0x2c74,0x0,0x66666667,0x2acc66,
	0x2c7e,0x0,0x66666667,0x2bba66,
	0x4e48,0x7ffe,0x0,0x2daa00,
	0x0154d9,0x7ffe,0x9a9a9a9a,0x27849a,
	0x011dc7,0x0,0xcdcdcdcd,0x2677cd,
	0x75cd,0x0,0x33333334,0x260d33,
	0x3ff6,0x0,0xcdcdcdcd,0x2601cd,
	0x76d3,0x7ffe,0x0,0x267a00
};

// plain_value-cipher_value (4 byte / a unit)
int diff_value_0_4_byte[] = {954,954,954,1210,954,954,1210,954,954,954};
// plain_value-cipher_value (1 byte / a unit)
int diff_value_8_12_byte[] = { -154,-154,102,102,102,-154,102,-154,102,102 };
int diff_value_12_14_byte[] = { 16490,16490,16490,16490,16490,16490,16490,16490,16490,16490 };
int diff_value_14_15_byte[] = {106,106,106,106,106,106,106,106,106,106};
int diff_value_15_16_byte[] = {64,64,64,64,64,64,64,64,64,64};


void print_4_byte_16(int text)
{
	for (int k = 0; k < 4; k++)
	{
		std::cout << std::hex << (text & 0x000000ff) << " ";
		text = text >> 8;
	}
}

void print_4_byte_10(int text)
{
	for (int k = 0; k < 4; k++)
	{
		std::cout << (text & 0x000000ff) << " ";
		text = text >> 8;
	}
}

void print_text(int text[])
{
	int row_num = 10;
	int col_num = 4;
	//int num = 10 * 4;
	for (int i = 0; i < row_num; i++)
	{
		for (int j = 0; j < col_num; j++)
		{
			int index = i*col_num + j;
			for (int k = 0; k < 4; k++)
			{
				std::cout << std::hex << (text[index] & 0x000000ff)<<" ";
				text[index] =text[index]>> 8;
			}
			/*int count = 0;
			//std::cout << std::hex << text[index] << std::endl;
			while (text[index] > 0)
			{
				count++;
				std::cout << std::hex << text[index] % 256 << " ";
				text[index] /= 256;
			}
			while (count < 4)
			{
				count++;
				std::cout << "00" << " ";
			}*/
		}
		std::cout << std::endl;
	}
}

void print_text_value(int text[])
{
	int row_num = 10;
	int col_num = 4;
	//int num = 10 * 4;
	for (int i = 0; i < row_num; i++)
	{
		for (int j = 0; j < col_num; j++)
		{
			int index = i*col_num + j;
			std::cout << text[index] << " ";
		}
		std::cout << std::endl;
	}
}

void cipher_to_plain(int text[])
{
	int row_num = 10;
	int col_num = 4;
	int pri_text[40];
	for (int i = 0; i < row_num; i++)
	{
		//std::cout << text[i*col_num] + diff_value[i] << std::endl;
		// 0-4 byte
		pri_text[i*col_num] = text[i*col_num] + diff_value_0_4_byte[i];
		// 4-8 byte 不变
		pri_text[i*col_num+1] = text[i*col_num+1];
		// 8-12 byte 字节加密
		pri_text[i*col_num + 2] = 0;
		int temp = 0;
		for (int k = 0; k < 4; k++)
		{
			temp= (temp|((text[i*col_num + 2] & 0x000000ff)+diff_value_8_12_byte[i]));
			//std::cout << std::hex << pri_text[i*col_num + 2] << " ";
			if (k == 3)
				break;
			text[i*col_num + 2] = text[i*col_num + 2] >> 8;
			temp = temp << 8;
		}
		for (int k = 0; k < 4; k++)
		{
			pri_text[i*col_num + 2] = pri_text[i*col_num + 2] | (temp & 0x000000ff);
			if(k==3)
				break;
			temp = temp >> 8;
			pri_text[i*col_num + 2] = pri_text[i*col_num + 2] << 8;
		}
		print_4_byte_16(pri_text[i*col_num+2]);
		std::cout << std::endl;
	}
	print_text(pri_text);
}

void compare_text_8_12_byte(int plain_text[],int cipher_text[])
{
	int row_num = 10;
	for (int i = 0; i < row_num; i++)
	{
		//std::cout << plain_text[i * 4 + 2] << " " << cipher_text[i * 4 + 2] << " " << plain_text[i * 4 + 2] - cipher_text[i * 4 + 2] << " ";
		//std::cout << plain_text[i * 4 + 2] % 65536 - cipher_text[i * 4 + 2] % 65536 << " " << plain_text[i * 4 + 2] / 65536 - cipher_text[i * 4 + 2] / 65536 << " ";
		//int plain_12_14 = plain_text[i * 4 + 2] / 65536;
		//int cipher_12_14 = cipher_text[i * 4 + 2] / 65536;
		//std::cout << plain_12_14 % 256 - cipher_12_14 % 256 << " " << plain_12_14 / 256 - cipher_12_14 / 256 << std::endl;
		int plain_text_ori = plain_text[i * 4 + 2];
		int cipher_text_ori = cipher_text[i * 4 + 2];
		for (int k = 0; k < 2; k++)
		{
			std::cout << (plain_text_ori & 0x0000ffff) - (cipher_text_ori & 0x0000ffff) << " ";
			plain_text_ori = plain_text_ori >> 16;
			cipher_text_ori = cipher_text_ori >> 16;
		}
		for (int k = 0; k < 4; k++)
		{
			std::cout << (plain_text[i * 4 + 2] & 0x000000ff) - (cipher_text[i * 4 + 2] & 0x000000ff)<<" ";
			plain_text[i * 4 + 2] = plain_text[i * 4 + 2] >>8;
			cipher_text[i * 4 + 2] = cipher_text[i * 4 + 2] >>8;
		}
		std::cout << std::endl;
	}
}

void compare_text_12_16_byte(int plain_text[], int cipher_text[])
{
	int row_num = 10;
	for (int i = 0; i < row_num; i++)
	{
		std::cout<<plain_text[i * 4 + 3]<<" "<<cipher_text[i * 4 + 3]<<" "<< plain_text[i * 4 + 3]-cipher_text[i * 4 + 3]<<" ";
		std::cout << plain_text[i * 4 + 3] % 65536 - cipher_text[i * 4 + 3] % 65536 << " "<<plain_text[i * 4 + 3] / 65536 - cipher_text[i * 4 + 3] / 65536<<" ";
		int plain_14_16 = plain_text[i * 4 + 3] / 65536;
		int cipher_14_16 = cipher_text[i * 4 + 3] / 65536;
		std::cout << plain_14_16 % 256 - cipher_14_16 % 256 << " " << plain_14_16 / 256 - cipher_14_16 / 256<<std::endl;
	}
}

void parse()
{

}

int main()
{
	//print_text_value(plaintext);
	//std::cout << std::endl;
	//print_text_value(ciphertext);
	//cipher_to_plain(ciphertext);
	//compare_text_8_12_byte(plaintext, ciphertext);
	cipher_to_plain(ciphertext);
	return 0;
}
