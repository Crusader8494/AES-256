#include <iostream>
#include <vector>
#include "AES_256_main.h"

std::vector<uint8_t> AES::AESEncrpyt(std::vector<uint8_t> inputState)
{
	AES::UnpackInputState(inputState);

	AddRoundKey(0);

	for (int i = 1; i != 14; i++)
	{
		EncryptNormalRound(i);
	}
	
	EncryptFinalRound(14);

	return PackOutputState();
}

std::vector<uint8_t> AES::AESDecrpyt(std::vector<uint8_t> inputState)
{
	AES::UnpackInputState(inputState);	

	for (int i = 14; i != 2; i--)
	{
		DecryptNormalRound(i);
	}

	DecryptFinalRound(1);

	AddRoundKey(0);

	return PackOutputState();
}

void AES::EncryptNormalRound(uint8_t roundNumber)
{
	SBoxState(false);
	ShiftRows(false);
	MixColumns(false);
	AddRoundKey(roundNumber);
}

void AES::EncryptFinalRound(uint8_t roundNumber)
{
	SBoxState(false);
	ShiftRows(false);
	AddRoundKey(roundNumber);
}

void AES::DecryptNormalRound(uint8_t roundNumber)
{
	SBoxState(true);
	ShiftRows(true);
	MixColumns(true);
	AddRoundKey(roundNumber);
}

void AES::DecryptFinalRound(uint8_t roundNumber)
{
	SBoxState(true);
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

std::vector<uint8_t> AES::PackOutputState()
{
	std::vector<uint8_t> returnVec = {};

	for (int i = 0; i != 4; i++)
	{
		for (int j = 0; j != 8; j++)
		{
			returnVec.push_back(state[i][j]);
		}
	}
	return returnVec;
}

void AES::ExpandKey()
{
	uint8_t tempRoundConstantArray[4] = { 0x00,0x00,0x00,0x00 };
	uint8_t tempRoundArray[4] = { 0x00,0x00,0x00,0x00 };

	for (int i = 0; i != 4; i++)
	{
		for (int j = 0; j != 8; j++)
		{
			initialAndExpandedKey[i][j][0] = initialKey[i][j]; //Set input key to position 0
		}
	}

	for (int i = 0; i != 14; i++)
	{
		tempRoundConstantArray[1] = initialAndExpandedKey[0][7][i]; //Rotate
		tempRoundConstantArray[2] = initialAndExpandedKey[1][7][i]; //Rotate
		tempRoundConstantArray[3] = initialAndExpandedKey[2][7][i]; //Rotate
		tempRoundConstantArray[0] = initialAndExpandedKey[3][7][i]; //Rotate

		tempRoundConstantArray[0] = SBoxByValue(false, tempRoundConstantArray[0]); //substitute
		tempRoundConstantArray[1] = SBoxByValue(false, tempRoundConstantArray[1]); //substitute
		tempRoundConstantArray[2] = SBoxByValue(false, tempRoundConstantArray[2]); //substitute
		tempRoundConstantArray[3] = SBoxByValue(false, tempRoundConstantArray[3]); //substitute

		initialAndExpandedKey[0][0][i + 1] = initialAndExpandedKey[0][0][i] ^ tempRoundConstantArray[0] ^ roundConstants[0][i]; //Column 0
		initialAndExpandedKey[1][0][i + 1] = initialAndExpandedKey[1][0][i] ^ tempRoundConstantArray[1] ^ roundConstants[1][i]; //Column 0
		initialAndExpandedKey[2][0][i + 1] = initialAndExpandedKey[2][0][i] ^ tempRoundConstantArray[2] ^ roundConstants[2][i]; //Column 0
		initialAndExpandedKey[3][0][i + 1] = initialAndExpandedKey[3][0][i] ^ tempRoundConstantArray[3] ^ roundConstants[3][i]; //Column 0

		initialAndExpandedKey[0][1][i + 1] = initialAndExpandedKey[0][1][i] ^ initialAndExpandedKey[0][0][i + 1]; //Column 1
		initialAndExpandedKey[1][1][i + 1] = initialAndExpandedKey[1][1][i] ^ initialAndExpandedKey[1][0][i + 1]; //Column 1
		initialAndExpandedKey[2][1][i + 1] = initialAndExpandedKey[2][1][i] ^ initialAndExpandedKey[2][0][i + 1]; //Column 1
		initialAndExpandedKey[3][1][i + 1] = initialAndExpandedKey[3][1][i] ^ initialAndExpandedKey[3][0][i + 1]; //Column 1

		initialAndExpandedKey[0][2][i + 1] = initialAndExpandedKey[0][2][i] ^ initialAndExpandedKey[0][1][i + 1]; //Column 2
		initialAndExpandedKey[1][2][i + 1] = initialAndExpandedKey[1][2][i] ^ initialAndExpandedKey[1][1][i + 1]; //Column 2
		initialAndExpandedKey[2][2][i + 1] = initialAndExpandedKey[2][2][i] ^ initialAndExpandedKey[2][1][i + 1]; //Column 2
		initialAndExpandedKey[3][2][i + 1] = initialAndExpandedKey[3][2][i] ^ initialAndExpandedKey[3][1][i + 1]; //Column 2

		initialAndExpandedKey[0][3][i + 1] = initialAndExpandedKey[0][3][i] ^ initialAndExpandedKey[0][2][i + 1]; //Column 3
		initialAndExpandedKey[1][3][i + 1] = initialAndExpandedKey[1][3][i] ^ initialAndExpandedKey[1][2][i + 1]; //Column 3
		initialAndExpandedKey[2][3][i + 1] = initialAndExpandedKey[2][3][i] ^ initialAndExpandedKey[2][2][i + 1]; //Column 3
		initialAndExpandedKey[3][3][i + 1] = initialAndExpandedKey[3][3][i] ^ initialAndExpandedKey[3][2][i + 1]; //Column 3

		initialAndExpandedKey[0][4][i + 1] = initialAndExpandedKey[0][4][i] ^ initialAndExpandedKey[0][3][i + 1]; //Column 4
		initialAndExpandedKey[1][4][i + 1] = initialAndExpandedKey[1][4][i] ^ initialAndExpandedKey[1][3][i + 1]; //Column 4
		initialAndExpandedKey[2][4][i + 1] = initialAndExpandedKey[2][4][i] ^ initialAndExpandedKey[2][3][i + 1]; //Column 4
		initialAndExpandedKey[3][4][i + 1] = initialAndExpandedKey[3][4][i] ^ initialAndExpandedKey[3][3][i + 1]; //Column 4

		initialAndExpandedKey[0][5][i + 1] = initialAndExpandedKey[0][5][i] ^ initialAndExpandedKey[0][4][i + 1]; //Column 5
		initialAndExpandedKey[1][5][i + 1] = initialAndExpandedKey[1][5][i] ^ initialAndExpandedKey[1][4][i + 1]; //Column 5
		initialAndExpandedKey[2][5][i + 1] = initialAndExpandedKey[2][5][i] ^ initialAndExpandedKey[2][4][i + 1]; //Column 5
		initialAndExpandedKey[3][5][i + 1] = initialAndExpandedKey[3][5][i] ^ initialAndExpandedKey[3][4][i + 1]; //Column 5

		initialAndExpandedKey[0][6][i + 1] = initialAndExpandedKey[0][6][i] ^ initialAndExpandedKey[0][5][i + 1]; //Column 6
		initialAndExpandedKey[1][6][i + 1] = initialAndExpandedKey[1][6][i] ^ initialAndExpandedKey[1][5][i + 1]; //Column 6
		initialAndExpandedKey[2][6][i + 1] = initialAndExpandedKey[2][6][i] ^ initialAndExpandedKey[2][5][i + 1]; //Column 6
		initialAndExpandedKey[3][6][i + 1] = initialAndExpandedKey[3][6][i] ^ initialAndExpandedKey[3][5][i + 1]; //Column 6

		initialAndExpandedKey[0][7][i + 1] = initialAndExpandedKey[0][7][i] ^ initialAndExpandedKey[0][6][i + 1]; //Column 7
		initialAndExpandedKey[1][7][i + 1] = initialAndExpandedKey[1][7][i] ^ initialAndExpandedKey[1][6][i + 1]; //Column 7
		initialAndExpandedKey[2][7][i + 1] = initialAndExpandedKey[2][7][i] ^ initialAndExpandedKey[2][6][i + 1]; //Column 7
		initialAndExpandedKey[3][7][i + 1] = initialAndExpandedKey[3][7][i] ^ initialAndExpandedKey[3][6][i + 1]; //Column 7
	}
}

void AES::SBoxState(bool forwardInverse)
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

uint8_t AES::SBoxByValue(bool forwardInverse, uint8_t value)
{
	if (forwardInverse == false)
	{
		uint8_t leftNib = (value >> 4) & 0x0F;
		uint8_t rightNib = value & 0x0F;

		value = forwardSBox[rightNib][leftNib]; //Confusing, sorry
	}
	else if (forwardInverse == true)
	{

		uint8_t leftNib = (value >> 4) & 0x0F;
		uint8_t rightNib = value & 0x0F;

		value = inverseSBox[rightNib][leftNib]; //Confusing, sorry
	}
	return value;
}

void AES::ShiftRows(bool forwardInverse)
{
	if (debugLogs == true)
	{
		printf("Pre Shift Rows:\n");
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
		printf("Post Shift Rows:\n");
		printState();
	}
	return;
}

void AES::MixColumns(bool forwardInverse)
{
	uint8_t result1, result2, result3, result4 = 0x00;

	if (debugLogs == true)
	{
		printf("Pre Mix Columns:\n");
		printState();
	}

	if (forwardInverse == false)
	{
		for (int columnNum = 0; columnNum != 8; columnNum++)
		{
			for (int rowNum = 0; rowNum != 4; rowNum++)
			{
				result1 = MultiplyInGF(state[0][columnNum], forwardMixColumnsMatrixPreFlipped[0][rowNum]);
				result2 = MultiplyInGF(state[1][columnNum], forwardMixColumnsMatrixPreFlipped[1][rowNum]);
				result3 = MultiplyInGF(state[2][columnNum], forwardMixColumnsMatrixPreFlipped[2][rowNum]);
				result4 = MultiplyInGF(state[3][columnNum], forwardMixColumnsMatrixPreFlipped[3][rowNum]);

				state[rowNum][columnNum] = result1 ^ result2 ^ result3 ^ result4;
			}
		}
		if (debugLogs == true) 
		{
			printf("Post Mix Columns:\n");
			printState();
		}
	}
	else if (forwardInverse == true)
	{
		for (int columnNum = 0; columnNum != 8; columnNum++)
		{
			for (int rowNum = 0; rowNum != 4; rowNum++)
			{
				result1 = MultiplyInGF(state[0][columnNum], inverseMixColumnsMatrixPreFlipped[0][rowNum]);
				result2 = MultiplyInGF(state[1][columnNum], inverseMixColumnsMatrixPreFlipped[1][rowNum]);
				result3 = MultiplyInGF(state[2][columnNum], inverseMixColumnsMatrixPreFlipped[2][rowNum]);
				result4 = MultiplyInGF(state[3][columnNum], inverseMixColumnsMatrixPreFlipped[3][rowNum]);

				state[rowNum][columnNum] = result1 ^ result2 ^ result3 ^ result4;
			}
		}
		if (debugLogs == true)
		{
			printf("Post Mix Columns:\n");
			printState();
		}
	}
}

uint8_t AES::MultiplyInGF(uint8_t stateValue ,uint8_t multiplier)
{
	if (multiplier == 0x01)
	{
		return stateValue;
	}

	uint32_t tempVal = static_cast<uint32_t>(stateValue);

	uint32_t tempValArray[7] = {0,0,0,0,0,0,0};

	if ((multiplier & 0x80) == 0x80) {
		tempValArray[6] = tempVal << 7;
	}
	if ((multiplier & 0x40) == 0x40) {
		tempValArray[5] = tempVal << 6;
	}
	if ((multiplier & 0x20) == 0x20) {
		tempValArray[4] = tempVal << 5;
	}
	if ((multiplier & 0x10) == 0x10) {
		tempValArray[3] = tempVal << 4;
	}
	if ((multiplier & 0x08) == 0x08) {
		tempValArray[2] = tempVal << 3;
	}
	if ((multiplier & 0x04) == 0x04) {
		tempValArray[1] = tempVal << 2;
	}
	if ((multiplier & 0x02) == 0x02) {
		tempValArray[0] = tempVal << 1;
	}
	//if ((multiplier & 0x01) == 0x01) { // Doesn't need to be executed
		//tempValArray[0] = tempVal << 0;
	//}
	
	uint32_t tempXORVal = 0x00000000;

	for (int i = 0; i < 7; i++)
	{
		tempXORVal ^= tempValArray[i];
	}
	
	if (tempXORVal <= 255)
	{
		return static_cast<uint8_t>(tempXORVal);
	}

	uint32_t modVal = 0x0000011B; // Irreducible polynomial

	uint32_t slidingMask = 0x80000000;

	uint8_t safetyCounter = 0;

	//find first 1 in bit vector
	while ((tempXORVal & slidingMask) != slidingMask)
	{
		slidingMask = slidingMask >> 1;
	}

	//shift first bit of modVal to that position
	while ((modVal & slidingMask) != slidingMask)
	{
		modVal = modVal << 1;
	}
		
	while (tempXORVal > 0x000000FF)
	{
		tempXORVal = tempXORVal ^ modVal;

		while ((slidingMask & tempXORVal) != slidingMask)
		{
			slidingMask = slidingMask >> 1;
			modVal = modVal >> 1;

			safetyCounter = safetyCounter + 1;

			if(safetyCounter >= 32)
			{
				throw 1;
			}
		}

	}
	return static_cast<uint8_t>(tempXORVal);
}

void AES::AddRoundKey(uint8_t roundNumber)
{
	if (debugLogs == true)
	{
		printf("Pre Round Key:\n");
		printState();
	}
	for (int i = 0; i != 4; i++)
	{
		for (int j = 0; j != 8; j++)
		{
			state[i][j] = state[i][j] ^ initialAndExpandedKey[i][j][roundNumber];
		}
	}
	if (debugLogs == true)
	{
		printf("Post Round Key:\n");
		printState();
	}
}

void AES::printState()
{
	//std::printf("printState:\n");
	std::printf("{%X,%X,%X,%X,%X,%X,%X,%X}\n", state[0][0], state[0][1], state[0][2], state[0][3], state[0][4], state[0][5], state[0][6], state[0][7]);
	std::printf("{%X,%X,%X,%X,%X,%X,%X,%X}\n", state[1][0], state[1][1], state[1][2], state[1][3], state[1][4], state[1][5], state[1][6], state[1][7]);
	std::printf("{%X,%X,%X,%X,%X,%X,%X,%X}\n", state[2][0], state[2][1], state[2][2], state[2][3], state[2][4], state[2][5], state[2][6], state[2][7]);
	std::printf("{%X,%X,%X,%X,%X,%X,%X,%X}\n", state[3][0], state[3][1], state[3][2], state[3][3], state[3][4], state[3][5], state[3][6], state[3][7]);
	return;
}