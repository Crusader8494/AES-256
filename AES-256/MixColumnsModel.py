def MultiplyInGF(a, b):
    temp = a
    list = []
    if (b & 0x80 == 0x80):
        list.append(temp << 7)
        #print("temp: " + hex(temp))
    if (b & 0x40 == 0x40):
        list.append(temp << 6)
        #print("temp: " + hex(temp))
    if (b & 0x20 == 0x20):
        list.append(temp << 5)
        #print("temp: " + hex(temp))
    if (b & 0x10 == 0x10):
        list.append(temp << 4)
        #print("temp: " + hex(temp))
    if (b & 0x08 == 0x08):
        list.append(temp << 3)
        #print("temp: " + hex(temp))
    if (b & 0x04 == 0x04):
        list.append(temp << 2)
        #print("temp: " + hex(temp))
    if (b & 0x02 == 0x02):
        list.append(temp << 1)
        #print("temp: " + hex(temp))
    if (b & 0x01 == 0x01):
        list.append(temp << 0)
        #print("temp: " + hex(temp))

    temp = 0
    for i in list:
        temp ^= i

    modVal = 0x11B
    #temp = temp << 4 # need this to move it up so I can mod by 5 bits
    mask = 0x80000000

    counter = 0

    #find first 1 in bit vector
    while((temp & mask) != mask):
        #print(hex(mask))
        mask = mask >> 1
    #print("Final Mask: " + hex(mask))

    #shift first bit of modVal to that position
    while((modVal & mask) != mask):
        #print(hex(modVal))
        modVal = modVal << 1
    #print("Final Modval: " + hex(modVal))

    while(temp > 0x000000FF):
        temp = temp ^ modVal
        #print("XORing " + hex(temp) + " with " + hex(modVal))
        #print("Temp XOR modVal Result: " + hex(temp))
        
        while((mask & temp) != mask):
            #print("Skipping 0")
            mask = mask >> 1
            modVal = modVal >> 1
        
        #print("New Mod Val: " + hex(modVal))
        counter = counter + 1
        if counter == 30:
            break

    #print("Orig Val: " + hex(a) + " // mod " + hex(b) + " // Final Remainder: " + hex(temp))
    return (temp & 0xFF)

def FlipMatrix(matrix):
    returnVal = []
    tempReturnVal = []
    for i in range(0,len(matrix[0])):
        for j in range(0,len(matrix[0])):
            tempReturnVal.append(matrix[j][i])
        returnVal.append(tempReturnVal.copy())
        tempReturnVal.clear()

    return returnVal


forwardMixColumnsMatrix = [
		[0x02,	0x03,	0x01,	0x01],
		[0x01,	0x02,	0x03,	0x01],
		[0x01,	0x01,	0x02,	0x03],
		[0x03,	0x01,	0x01,	0x02]]

inverseMixColumnsMatrix= [
		[0x0E,	0x0B,	0x0D,	0x09],
		[0x09,	0x0E,	0x0B,	0x0D],
		[0x0D,	0x09,	0x0E,	0x0B],
		[0x0B,	0x0D,	0x09,	0x0E]]


def MixColumns(inputState):
    #encode
    tempList = []
    tempAnswer = 0
    tempInput = []
    tempInput = FlipMatrix(inputState)
    tempRow = []
    encodedData = []

    for i in range(0,4):
        for j in range(0,4):
            for k in range(0,4):
                a = tempInput[i][k]
                b = forwardMixColumnsMatrix[j][k]
                tempList.append(MultiplyInGF(a,b))
            
            for k in tempList:
                tempAnswer ^= k

            tempList.clear()
            tempRow.append(tempAnswer)
            tempAnswer = 0

        encodedData.append(tempRow.copy())
        tempRow.clear()
    return FlipMatrix(encodedData)

def UnMixColumns(inputState):
    #decode
    tempList = []
    tempAnswer = 0
    tempInput = []
    tempInput = FlipMatrix(inputState)
    tempRow = []
    decodedData = []

    for i in range(0,4):
        for j in range(0,4):
            for k in range(0,4):
                a = tempInput[i][k]
                b = inverseMixColumnsMatrix[j][k]
                tempList.append(MultiplyInGF(a,b))
            
            for k in tempList:
                tempAnswer ^= k

            tempList.clear()
            tempRow.append(tempAnswer)
            tempAnswer = 0

        decodedData.append(tempRow.copy())
        tempRow.clear()
    return FlipMatrix(decodedData)


inputArray = [
        [0xd4,0xe0,0xb8,0x1e],
        [0xbf,0xb4,0x41,0x27],
        [0x5d,0x52,0x11,0x98],
        [0x30,0xae,0xf1,0xe5]]

print("Plaintext========================")
print(inputArray)
resultMatrix = MixColumns(inputArray)
print("Ciphertext========================")
print(resultMatrix)
newResultMatrix = UnMixColumns(resultMatrix)
print("Decoded Ciphertext=================")
print(newResultMatrix)