#include <iostream>
#include <vector>
#include "main.h"
#include "AES_256_main.h"

int main() {

	std::vector<uint8_t> cryptoKey;

	for (int i = 0; i != 32; i++)
	{
		cryptoKey.push_back(static_cast<uint8_t>(i));
	}

	AES crypto(cryptoKey);

	std::vector<uint8_t> plainText;

	for (int i = 0; i != 32; i++)
	{
		plainText.push_back(static_cast<uint8_t>(32 - i));
	}

	crypto.AESEncrpyt(plainText);

	return 0;
}