#include <iostream>
#include <vector>
#include "main.h"
#include "AES_256_main.h"

int main() {

	std::vector<uint8_t> cryptoKey;

	for (uint8_t i = 0; i != 32; i++)
	{
		cryptoKey.push_back(i*4);
	}

	AES crypto(cryptoKey,true);

	std::vector<uint8_t> plainText;

	for (uint8_t i = 0; i != 32; i++)
	{
		plainText.push_back(32 - i);
	}

	std::vector<uint8_t> cipherText = crypto.AESEncrpyt(plainText);

	std::vector<uint8_t> decipheredText = crypto.AESDecrpyt(cipherText);

	return 0;
}