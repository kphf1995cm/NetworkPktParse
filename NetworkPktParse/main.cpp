
/*
 * func: parse network packet
 * name: peng kp18@mails.tsinghua.edu.cn
 * time: 2019-2-11
 */

#include<iostream>
#include<iomanip>
#include<stdlib.h>
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

Data init()
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
	return data;
}

// a unit is 32 byte
uint32_t plaintext[] = {
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

uint32_t ciphertext[] = {
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
// 12-13 byte 单字节加密 
// 13-14 byte 单字节加密 
// 14-16 byte 双字节加密 16490
uint32_t packet[] = {
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

// 0-4 byte int 
// 4-8 byte useless
// 8-16 byte double
// plain_value-cipher_value (4 byte / a unit)
int diff_value_0_4_byte[] = {954,954,954,1210,954,954,1210,954,954,954};
// plain_value-cipher_value (1 byte / a unit)
int diff_value_8_12_byte[] = { -154,-154,102,102,102,-154,102,-154,102,102 };
int diff_value_14_16_byte[] = { 16490,16490,16490,16490,16490,16490,16490,16490,16490,16490 };
int diff_value_12_13_byte[] = {-154,-154,102,102,102,-154,102,-154,102,102};
int diff_value_13_14_byte[] = {-122,-122,134,134,134,134,134,-122,134,134};
int diff_value_12_14_byte[] = {-31386,-31386,34406,34406,34406,34150,34406,-31386,34406,34406};

void print_4_byte_16(uint32_t text)
{
	for (int k = 0; k < 4; k++)
	{
		std::cout << std::hex << (text & 0x000000ff) << " ";
		text = text >> 8;
	}
}

void print_4_byte_10(uint32_t text)
{
	for (int k = 0; k < 4; k++)
	{
		std::cout << (text & 0x000000ff) << " ";
		text = text >> 8;
	}
}

void print_text(uint32_t text1[])
{
	int row_num = 10;
	int col_num = 4;

	uint32_t text[40];
	for (int i = 0; i < 40; i++)
		text[i] = text1[i];
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


void print_data(Data &data)
{
	std::cout << "int" << " " << "double" << std::endl;
	std::cout <<std::dec<< data.av1 << " " << data.ap1 << std::endl;
	std::cout << data.av2 << " " << data.ap2 << std::endl;
	std::cout << data.av3 << " " << data.ap3 << std::endl;
	std::cout << data.av4 << " " << data.ap4 << std::endl;
	std::cout << data.av5 << " " << data.ap5 << std::endl;
	std::cout << data.bv1 << " " << data.bp1 << std::endl;
	std::cout << data.bv2 << " " << data.bp2 << std::endl;
	std::cout << data.bv3 << " " << data.bp3 << std::endl;
	std::cout << data.bv4 << " " << data.bp4 << std::endl;
	std::cout << data.bv5 << " " << data.bp5 << std::endl;
}

uint32_t* cipher_to_plain(uint32_t text[])
{
	int row_num = 10;
	int col_num = 4;
	uint32_t* pri_text=new uint32_t[40];
	for (int i = 0; i < row_num; i++)
	{
		//std::cout << text[i*col_num] + diff_value[i] << std::endl;
		// 0-4 byte
		pri_text[i*col_num] = text[i*col_num] + diff_value_0_4_byte[i];
		// 4-8 byte 不变
		pri_text[i*col_num+1] = text[i*col_num+1];
		// 8-12 byte 字节加密
		pri_text[i*col_num + 2] = 0;
		uint32_t temp = 0;
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
		std::cout << "8_12:" << std::hex << pri_text[i*col_num + 2] << std::endl;
		//print_4_byte_16(pri_text[i*col_num+2]);
		//std::cout << std::endl;
		// 12-16 byte
		uint32_t value_12_13 = (text[i*col_num + 3] & 0x000000ff)+diff_value_12_13_byte[i];
		//std::cout << std::hex << value_12_14 << std::endl;
		uint32_t value_13_14 = ((text[i*col_num + 3] & 0x0000ff00) >> 8) + diff_value_13_14_byte[i];
		uint32_t value_14_16 = ((text[i*col_num + 3] & 0xffff0000)>>16) + diff_value_14_16_byte[i];
		std::cout <<"14_16 13_14 12_13:"<< std::hex << value_14_16<<" "<<value_13_14<<" "<<value_12_13 << std::endl;
		pri_text[i*col_num + 3] = (value_12_13&0x000000ff);
		//pri_text[i*col_num + 3] = pri_text[i*col_num + 3];
		pri_text[i*col_num + 3] = pri_text[i*col_num + 3] | ((value_13_14 << 8)&0x0000ff00);
		pri_text[i*col_num + 3] = pri_text[i*col_num + 3] | ((value_14_16<<16)&0xffff0000);
	}
	//print_text(pri_text);
	return pri_text;
}

uint32_t* cipher_to_plain2(uint32_t text[])
{
	int row_num = 10;
	int col_num = 4;
	uint32_t* pri_text = new uint32_t[40];
	for (int i = 0; i < row_num; i++)
	{
		//std::cout << text[i*col_num] + diff_value[i] << std::endl;
		// 0-4 byte
		pri_text[i*col_num] = text[i*col_num] + diff_value_0_4_byte[i];
		// 4-8 byte 不变
		pri_text[i*col_num + 1] = text[i*col_num + 1];
		// 8-12 byte 字节加密
		pri_text[i*col_num + 2] = 0;
		uint32_t temp = 0;
		for (int k = 0; k < 4; k++)
		{
			temp = (temp | ((text[i*col_num + 2] & 0x000000ff) + diff_value_8_12_byte[i]));
			//std::cout << std::hex << pri_text[i*col_num + 2] << " ";
			if (k == 3)
				break;
			text[i*col_num + 2] = text[i*col_num + 2] >> 8;
			temp = temp << 8;
		}
		for (int k = 0; k < 4; k++)
		{
			pri_text[i*col_num + 2] = pri_text[i*col_num + 2] | (temp & 0x000000ff);
			if (k == 3)
				break;
			temp = temp >> 8;
			pri_text[i*col_num + 2] = pri_text[i*col_num + 2] << 8;
		}
		//print_4_byte_16(pri_text[i*col_num+2]);
		//std::cout << std::endl;
		// 12-16 byte
		uint32_t value_12_14 = (text[i*col_num + 3] & 0x0000ffff) + diff_value_12_14_byte[i];
		uint32_t value_14_16 = ((text[i*col_num + 3] & 0xffff0000) >> 16) + diff_value_14_16_byte[i];
		std::cout << "14_16 12_14:" << std::hex << value_14_16 << " " << value_12_14<< std::endl;
		pri_text[i*col_num + 3] = value_12_14;
		pri_text[i*col_num + 3] = pri_text[i*col_num + 3] | (value_14_16 << 16);
	}
	//print_text(pri_text);
	return pri_text;
}

Data plain_to_data(uint32_t text[])
{
	Data data;
	// int
	data.av1 = text[0];
	data.av2 = text[4];
	data.av3 = text[8];
	data.av4 = text[12];
	data.av5 = text[16];
	data.bv1 = text[20];
	data.bv2 = text[24];
	data.bv3 = text[28];
	data.bv4 = text[32];
	data.bv5 = text[36];
	// double
	uint64_t text_3_2[10];
	for (int i = 0; i < 10; i++)
	{
		memcpy(&text_3_2[i], &text[i * 4 + 3], 4);
		text_3_2[i] = text_3_2[i] << 32;
		memcpy(&text_3_2[i], &text[i * 4 + 2], 4);
		//std::cout << std::hex << text_3_2[i] << std::endl;
	}
	memcpy(&data.ap1, &text_3_2[0], 8);
	memcpy(&data.ap2, &text_3_2[1], 8);
	memcpy(&data.ap3, &text_3_2[2], 8);
	memcpy(&data.ap4, &text_3_2[3], 8);
	memcpy(&data.ap5, &text_3_2[4], 8);
	memcpy(&data.bp1, &text_3_2[5], 8);
	memcpy(&data.bp2, &text_3_2[6], 8);
	memcpy(&data.bp3, &text_3_2[7], 8);
	memcpy(&data.bp4, &text_3_2[8], 8);
	memcpy(&data.bp5, &text_3_2[9], 8);
	print_data(data);
	return data;
}

bool judge(uint32_t plain_text[],uint32_t dst_text[])
{
	//print_text(plain_text);
	//print_text(dst_text);
	int row_num = 10;
	int col_num = 4;
	for (int i = 0; i < row_num; i++)
	{
		for (int j = 0; j < col_num; j++)
		{
			//std::cout << plain_text[i*col_num + j] - dst_text[i*col_num + j] << " ";
			if (plain_text[i*col_num + j] != dst_text[i*col_num + j])
				return false;
		}
		//std::cout << std::endl;
	}
	return true;
}

void compare_text_8_12_byte(uint32_t plain_text[],uint32_t cipher_text[])
{
	int row_num = 10;
	for (int i = 0; i < row_num; i++)
	{
		//std::cout << plain_text[i * 4 + 2] << " " << cipher_text[i * 4 + 2] << " " << plain_text[i * 4 + 2] - cipher_text[i * 4 + 2] << " ";
		//std::cout << plain_text[i * 4 + 2] % 65536 - cipher_text[i * 4 + 2] % 65536 << " " << plain_text[i * 4 + 2] / 65536 - cipher_text[i * 4 + 2] / 65536 << " ";
		//int plain_12_14 = plain_text[i * 4 + 2] / 65536;
		//int cipher_12_14 = cipher_text[i * 4 + 2] / 65536;
		//std::cout << plain_12_14 % 256 - cipher_12_14 % 256 << " " << plain_12_14 / 256 - cipher_12_14 / 256 << std::endl;
		uint32_t plain_8_12 = plain_text[i * 4 + 2];
		uint32_t cipher_8_12 = cipher_text[i * 4 + 2];
		for (int k = 0; k < 2; k++)
		{
			std::cout << (plain_8_12 & 0x0000ffff) - (cipher_8_12 & 0x0000ffff) << " ";
			plain_8_12 = plain_8_12 >> 16;
			cipher_8_12 = cipher_8_12 >> 16;
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

void compare_text_8_14_byte(uint32_t plain_text[], uint32_t cipher_text[])
{
	int row_num = 10;
	for (int i = 0; i < row_num; i++)
	{
		uint32_t plain_8_12 = plain_text[i * 4 + 2];
		uint32_t cipher_8_12 = cipher_text[i * 4 + 2];

		uint32_t plain_12_16 = plain_text[i * 4 + 3];
		uint32_t cipher_12_16 = cipher_text[i * 4 + 3];

		int64_t plain_8_14 = 0;
		int64_t cipher_8_14 = 0;

		memcpy(&plain_8_14, &plain_12_16, 2);
		plain_8_14 = plain_8_14 << 32;
		memcpy(&plain_8_14, &plain_8_12, 4);

		memcpy(&cipher_8_14, &cipher_12_16, 2);
		cipher_8_14 = cipher_8_14 << 32;
		memcpy(&cipher_8_14, &cipher_8_12, 4);
		//std::cout <<"plain_8_14:"<<std::hex<< plain_8_14 << std::endl;
		//std::cout << "cipher_8_14:"<<std::hex<< cipher_8_14 << std::endl;

		std::cout << "8_14:";
		std::cout << std::dec<<plain_8_14  + cipher_8_14 << " ";

		std::cout << "three bytes:";
		for (int k = 0; k < 2; k++)
		{
			std::cout << (plain_8_14 & 0x0000000000ffffff) - (cipher_8_14 & 0x0000000000ffffff) << " ";
			plain_8_14 = plain_8_14 >> 24;
			cipher_8_14 = cipher_8_14 >> 24;
		}

		std::cout << "double bytes:";
		for (int k = 0; k < 3; k++)
		{
			std::cout << (plain_8_14 & 0x000000000000ffff) - (cipher_8_14 & 0x000000000000ffff) << " ";
			plain_8_14 = plain_8_14 >> 16;
			cipher_8_14 = cipher_8_14 >> 16;
		}

		std::cout << "single bytes:";
		for (int k = 0; k < 6; k++)
		{
			std::cout << (plain_8_14 & 0x00000000000000ff) + (cipher_8_14 & 0x00000000000000ff) << " ";
			plain_8_14 = plain_8_14 >> 8;
			cipher_8_14 = cipher_8_14 >> 8;
		}
		std::cout << std::endl;
	}
}

void compare_text_12_16_byte(uint32_t plain_text[], uint32_t cipher_text[])
{
	int row_num = 10;
	for (int i = 0; i < row_num; i++)
	{
		//std::cout<<plain_text[i * 4 + 3]<<" "<<cipher_text[i * 4 + 3]<<" "<< plain_text[i * 4 + 3]-cipher_text[i * 4 + 3]<<" ";
		std::cout <<"12_14:"<<(int) (plain_text[i * 4 + 3] % 65536 - cipher_text[i * 4 + 3] % 65536) << " "<<"14_16:"<<plain_text[i * 4 + 3] / 65536 - cipher_text[i * 4 + 3] / 65536<<" ";
		uint32_t plain_12_14 = plain_text[i * 4 + 3] % 65536;
		uint32_t cipher_12_14 = cipher_text[i * 4 + 3] % 65536;
		std::cout <<"12_13:"<<(int)(plain_12_14 % 256 - cipher_12_14 % 256) << " " <<"13_14:"<< (int)(plain_12_14 / 256 - cipher_12_14 / 256)<<std::endl;
	} 
}

void compare_text_8_16_byte(uint32_t plain_text[], uint32_t cipher_text[])
{
	int row_num = 10;
	for (int i = 0; i < row_num; i++)
	{
		uint32_t plain_8_12 = plain_text[i * 4 + 2];
		uint32_t cipher_8_12 = cipher_text[i * 4 + 2];

		uint32_t plain_12_16 = plain_text[i * 4 + 3];
		uint32_t cipher_12_16 = cipher_text[i * 4 + 3];

		int64_t plain_8_16 = 0;
		int64_t cipher_8_16 = 0;

		memcpy(&plain_8_16, &plain_12_16, 4);
		plain_8_16 = plain_8_16 << 32;
		memcpy(&plain_8_16, &plain_8_12, 4);

		memcpy(&cipher_8_16, &cipher_12_16,4);
		cipher_8_16 = cipher_8_16 << 32;
		memcpy(&cipher_8_16, &cipher_8_12, 4);
		//std::cout <<"plain_8_16:"<<std::hex<< plain_8_16 << std::endl;
		//std::cout << "cipher_8_16:"<<std::hex<< cipher_8_16 << std::endl;

		//std::cout << "8_16:";
		//std::cout << std::dec << plain_8_16 - cipher_8_16 << " ";

		/*std::cout << "four bytes:";
		for (int k = 0; k < 2; k++)
		{
			std::cout << (plain_8_16 & 0x00000000ffffffff) + (cipher_8_16 & 0x0000000000ffffff) << " ";
			plain_8_16 = plain_8_16 >> 32;
			cipher_8_16 = cipher_8_16 >> 32;
		}*/

		/*std::cout << "double bytes:";
		for (int k = 0; k < 4; k++)
		{
			std::cout << (plain_8_16 & 0x000000000000ffff) - (cipher_8_16 & 0x000000000000ffff) << " ";
			plain_8_16 = plain_8_16 >> 16;
			cipher_8_16 = cipher_8_16 >> 16;
		}*/

		std::cout << "single bytes:";
		for (int k = 0; k < 8; k++)
		{
			std::cout << (plain_8_16 & 0x00000000000000ff) - (cipher_8_16 & 0x00000000000000ff) << " ";
			plain_8_16 = plain_8_16 >> 8;
			cipher_8_16 = cipher_8_16 >> 8;
		}
		std::cout << std::endl;
	}
}

void view_double_bit()
{
	const int num = 10;
	double price[] = {1000.9,1100.8,1200.7,1260.2,1384.1,990.5,987.3,960.9,957.8,924.1};
	uint64_t price_int[num];
	for (int i = 0; i < num; i++)
	{
		memcpy(&price_int[i], &price[i], 8);
	}
	for (int i = 0; i < num; i++)
		cout << hex << price_int[i]<< endl;
}

int main()
{
	//print_text_value(plaintext);
	//std::cout << std::endl;
	//print_text_value(ciphertext);
	//cipher_to_plain(ciphertext);
	//compare_text_8_16_byte(plaintext, ciphertext);
	
	std::cout << "ciphertext" << std::endl;
	print_text(ciphertext);
	uint32_t * dst_text = cipher_to_plain(ciphertext);
	std::cout << "plaintext" << std::endl;
	print_text(dst_text);
	if (judge(plaintext, dst_text))
	{
		std::cout << "True" << std::endl;
		plain_to_data(dst_text);
	}
	else
		std::cout << "False" << std::endl;

	std::cout << "packet:" << std::endl;
	print_text(packet);
	uint32_t * src_packet = cipher_to_plain(packet);
	std::cout << "src_packet:" << std::endl;
	print_text(src_packet);
	plain_to_data(src_packet);
	

	//view_double_bit();
	return 0;
}
