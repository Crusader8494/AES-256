#include <iostream>
#include <vector>
#include "AES_256_main.h"

std::vector<uint8_t> AES::AESEncrpyt(std::vector<uint8_t> inputState)
{
	AES::InitializeArrays();

	AES::UnpackInputState(inputState);


	AddRoundKey(0);

	for (int i = 1; i != 15; i++)
	{
		EncryptNormalRound(i);
	}
	
	EncryptFinalRound(15);


	std::vector<uint8_t> returnVec;

	return returnVec;
}

std::vector<uint8_t> AES::AESDecrpyt(std::vector<uint8_t> inputState)
{
	AES::InitializeArrays();

	AES::UnpackInputState(inputState);

	AddRoundKey(0);

	for (int i = 15; i != 0; i--)
	{
		DecryptNormalRound(i);
	}

	DecryptFinalRound(0);

	std::vector<uint8_t> returnVec;

	return returnVec;
}

void AES::EncryptNormalRound(uint8_t roundNumber)
{
	SBox(false);
	ShiftRows(false);
	MixColumns(false);
	AddRoundKey(roundNumber);
}

void AES::EncryptFinalRound(uint8_t roundNumber)
{
	SBox(false);
	ShiftRows(false);
	AddRoundKey(roundNumber);
}

void AES::DecryptNormalRound(uint8_t roundNumber)
{
	SBox(true);
	ShiftRows(true);
	MixColumns(true);
	AddRoundKey(roundNumber);
}

void AES::DecryptFinalRound(uint8_t roundNumber)
{
	SBox(true);
	ShiftRows(true);
	AddRoundKey(roundNumber);
}

void AES::UnpackInputState(std::vector<uint8_t> inputState)
{
	if (inputState.size() != 32)
	{
		std::cout << "Input Vector of invalid length";
		throw 1;
	}
	for (int i = 0; i != 32; i++)
	{
		if (debugLogs == true)
		{
			std::printf("UnpackInputState: Placing data %u at state[%u][%u] \n", inputState.at(i), i / 8, i % 8);
		}

		state[i / 8][i % 8] = inputState.at(i);
	}
}

void AES::PackOutputState(std::vector<uint8_t> inputState)
{

}

void AES::ExpandKey()
{

}

void AES::SBox(bool forwardInverse)
{
	if (forwardInverse == false)
	{
		for (int i = 0; i != 4; i++)
		{
			for (int j = 0; j != 8; j++)
			{
				uint8_t leftNib = (state[i][j] >> 4) & 0x0F;
				uint8_t rightNib = state[i][j] & 0x0F;

				state[i][j] = forwardSBox[rightNib][leftNib]; //Confusing, sorry
			}
		}
	}
	else if (forwardInverse == true)
	{
		for (int i = 0; i != 4; i++)
		{
			for (int j = 0; j != 8; j++)
			{
				uint8_t leftNib = (state[i][j] >> 4) & 0x0F;
				uint8_t rightNib = state[i][j] & 0x0F;

				state[i][j] = inverseSBox[rightNib][leftNib]; //Confusing, sorry
			}
		}
	}
	return;
}

void AES::ShiftRows(bool forwardInverse)
{
	if (debugLogs == true)
	{
		printState();
	}

	//row 0
	//null

	uint8_t tempArray[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	//row 1////////////////////////////////////////////////////
	for (int i = 0; i != 8; i++)
	{
		tempArray[i] = state[1][i];
	}
	if (forwardInverse == false)
	{
		state[1][0] = tempArray[7];
		state[1][1] = tempArray[0];
		state[1][2] = tempArray[1];
		state[1][3] = tempArray[2];
		state[1][4] = tempArray[3];
		state[1][5] = tempArray[4];
		state[1][6] = tempArray[5];
		state[1][7] = tempArray[6];
	}
	else if (forwardInverse == true)
	{
		state[1][0] = tempArray[1];
		state[1][1] = tempArray[2];
		state[1][2] = tempArray[3];
		state[1][3] = tempArray[4];
		state[1][4] = tempArray[5];
		state[1][5] = tempArray[6];
		state[1][6] = tempArray[7];
		state[1][7] = tempArray[0];
	}

	//row 2////////////////////////////////////////////////////
	for (int i = 0; i != 8; i++)
	{
		tempArray[i] = state[2][i];
	}
	if (forwardInverse == false)
	{
		state[2][0] = tempArray[5];
		state[2][1] = tempArray[6];
		state[2][2] = tempArray[7];
		state[2][3] = tempArray[0];
		state[2][4] = tempArray[1];
		state[2][5] = tempArray[2];
		state[2][6] = tempArray[3];
		state[2][7] = tempArray[4];
	}
	else if (forwardInverse == true)
	{
		state[2][0] = tempArray[3];
		state[2][1] = tempArray[4];
		state[2][2] = tempArray[5];
		state[2][3] = tempArray[6];
		state[2][4] = tempArray[7];
		state[2][5] = tempArray[0];
		state[2][6] = tempArray[1];
		state[2][7] = tempArray[2];
	}
	//row 3////////////////////////////////////////////////////
	for (int i = 0; i != 8; i++)
	{
		tempArray[i] = state[3][i];
	}
	if (forwardInverse == false)
	{
		state[3][0] = tempArray[4];
		state[3][1] = tempArray[5];
		state[3][2] = tempArray[6];
		state[3][3] = tempArray[7];
		state[3][4] = tempArray[0];
		state[3][5] = tempArray[1];
		state[3][6] = tempArray[2];
		state[3][7] = tempArray[3];
	}
	else if (forwardInverse == true)
	{
		state[3][0] = tempArray[4];
		state[3][1] = tempArray[5];
		state[3][2] = tempArray[6];
		state[3][3] = tempArray[7];
		state[3][4] = tempArray[0];
		state[3][5] = tempArray[1];
		state[3][6] = tempArray[2];
		state[3][7] = tempArray[3];

	}

	if (debugLogs == true)
	{
		printState();
	}
	return;
}

void AES::MixColumns(bool forwardInverse)
{
	uint8_t result1, result2, result3, result4 = 0x00;

	if (forwardInverse == false)
	{
		for (int columnNum = 0; columnNum != 8; columnNum++)
		{
			for (int rowNum = 0; rowNum != 4; rowNum++)
			{
				result1 = MultiplyInGF(state[rowNum][columnNum], forwardMixColumnsMatrix[rowNum][0]);
				result2 = MultiplyInGF(state[rowNum][columnNum], forwardMixColumnsMatrix[rowNum][1]);
				result3 = MultiplyInGF(state[rowNum][columnNum], forwardMixColumnsMatrix[rowNum][2]);
				result4 = MultiplyInGF(state[rowNum][columnNum], forwardMixColumnsMatrix[rowNum][3]);

				state[rowNum][columnNum] = result1 ^ result2 ^ result3 ^ result4;
			}
		}
	}
	else if (forwardInverse == true)
	{

	}
}

uint8_t AES::MultiplyInGF(uint8_t stateValue ,uint8_t multiplier)
{
	uint16_t tempVal = static_cast<uint16_t>(stateValue);
	uint16_t tempMult = static_cast<uint16_t>(multiplier);

	uint16_t origTempVal = 0x0000;

	if (tempMult == 0x0001)
	{
		return static_cast<uint8_t>(tempVal);
	}
	else if (tempMult == 0x0002)
	{
		tempVal = tempVal * 0x0002;

		if ((tempVal & 0x0100) == 0x0100)
		{
			tempVal = tempVal ^ 0x011B; //Irreduciable Polynomial
		}

		return static_cast<uint8_t>(tempVal);
	}
	else if (tempMult == 0x0003)
	{
		origTempVal = tempVal; //store for later

		tempVal = tempVal * 0x0002; //first, by 2

		if ((tempVal & 0x0100) == 0x0100)
		{
			tempVal = tempVal ^ 0x011B; //Irreduciable Polynomial
		}

		tempVal = tempVal ^ origTempVal; //used here

		return static_cast<uint8_t>(tempVal);
	}
	//more needed for decrypt
	else
	{
		std::cout << "Invalid Multiplier Value";
		throw 1;
	}

	tempVal = tempVal * tempMult;
}

void AES::AddRoundKey(uint8_t roundNumber)
{
	//for(int i = 0; i != )
}

void AES::printState()
{
	std::printf("printState:\n");
	std::printf("{%X,%X,%X,%X,%X,%X,%X,%X}\n", state[0][0], state[0][1], state[0][2], state[0][3], state[0][4], state[0][5], state[0][6], state[0][7]);
	std::printf("{%X,%X,%X,%X,%X,%X,%X,%X}\n", state[1][0], state[1][1], state[1][2], state[1][3], state[1][4], state[1][5], state[1][6], state[1][7]);
	std::printf("{%X,%X,%X,%X,%X,%X,%X,%X}\n", state[2][0], state[2][1], state[2][2], state[2][3], state[2][4], state[2][5], state[2][6], state[2][7]);
	std::printf("{%X,%X,%X,%X,%X,%X,%X,%X}\n", state[3][0], state[3][1], state[3][2], state[3][3], state[3][4], state[3][5], state[3][6], state[3][7]);
	return;
}