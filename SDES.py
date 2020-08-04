 # Homework 1.a ==> Simplified DES

# performs a left shift on n, wrapping the last bit around to the front
# assumes n is 5 bits
def circularShift(n):
    n2 = (n << 1) & 0b11111
    # 5th bit was a 1 - add 1 to n2
    if n > 0b01111:
        n2 += 1
    return n2

# returns the value of the ith bit from left (1 or 0):
def getIthBit(n, l, i):
    bit = n & (1 << (l - i))
    return bit >> (l - i)

# generates the 2 8-bit subkeys from a 10-bit initial key:
def getKeys(K, Keys):
    # Rearrange the bits of K by using the PC1 permutation:
    perm = 0
    for i in PC1:
        perm = perm << 1
        if getIthBit(K, 10, i) != 0:
            perm += 1
    # Divide 10-bit permutation into two 5-bit numbers
    left = perm >> 5
    right = perm & 0b11111
    # Perform left shifts (wrap last bit around)
    left = circularShift(left)
    right = circularShift(right)
    combo = (left << 5) + right
    # Get K1 by using the PC2 permutation:
    K1 = 0
    for i in PC2:
        K1 = K1 << 1
        if getIthBit(combo, 10, i) != 0:
            K1 += 1
    Keys[0] = K1
    # Perform 2 left shifts for second key:
    left = circularShift(left)
    left = circularShift(left)
    right = circularShift(right)
    right = circularShift(right)
    combo = (left << 5) + right
    # Get K2 by using the PC2 permutation:
    K2 = 0
    for i in PC2:
        K2 = K2 << 1
        if getIthBit(combo, 10, i) != 0:
            K2 += 1
    Keys[1] = K2

# turns 4-bit number, n, into 2-bit number using substitution matrix, S:
def substitute(n, S):
    row = 0
    row += getIthBit(n, 4, 1)
    row = row << 1
    row += getIthBit(n, 4, 4)
    col = 0
    col += getIthBit(n, 4, 2)
    col = col << 1
    col += getIthBit(n, 4, 3)
    return S[row][col]

# F function takes in 4-bit number, n, and 8-bit key, K
# returns a rearranged 4-bit number
def F(n, K):
    # use expansion permutation (EP) on n:
    expanded = 0
    for i in EP:
        expanded = expanded << 1
        if getIthBit(n, 4, i) != 0:
            expanded += 1
    # XOR with 8-bit key:
    expanded = expanded ^ K
    # divide 8-bits into two 4-bit numbers:
    left = expanded >> 4
    right = expanded & 0b1111
    # left 4 bits use S0, right 4 bits use S1:
    left = substitute(left, S0)
    right = substitute(right, S1)
    # combine into a 4-bit number:
    combo = (left << 2) + right
    # use P4 to get return value:
    r = 0
    for i in P4:
        r = r << 1
        if getIthBit(combo, 4, i) != 0:
            r += 1
    return r

# converts 8-bit plain text into 8-bit cypher text 
def encryptByte(P, K):
    # get K1 and K2:
    Keys = [0, 0]
    getKeys(K, Keys)
    K1 = Keys[0]
    K2 = Keys[1]
    # use initial permutation (IP) on P:
    perm = 0
    for i in IP:
        perm = perm << 1
        if getIthBit(P, 8, i) != 0:
            perm += 1
    # divide byte into two 4-bit numbers:
    left = perm >> 4
    right = perm & 0b1111
    # right 4 bits are rearranged using F function and K1:
    F1 = F(right, K1)
    # XOR with left 4 bits:
    right2 = left ^ F1
    # left 4 bits are rearranged using F function and K2:
    F2 = F(right2, K2)
    # XOR with right 4 bits:
    left2 = F2 ^ right
    # combine into an 8-bit number:
    combo = (left2 << 4) + right2
    # use inverse initial permutation (FP) on comb to get 8-bit cypher text:
    T = 0
    for i in FP:
        T = T << 1
        if getIthBit(combo, 8, i) != 0:
            T += 1
    return T

# converts 8-bit cypher text into 8-bit plain text:
def decryptByte(T, K):
    # get K1 and K2:
    Keys = [0, 0]
    getKeys(K, Keys)
    K1 = Keys[0]
    K2 = Keys[1]
    # use initial permutation (IP) on T:
    perm = 0
    for i in IP:
        perm = perm << 1
        if getIthBit(T, 8, i) != 0:
            perm += 1
    # divide byte into two 4-bit numbers:
    left = perm >> 4
    right = perm & 0b1111
    # right 4 bits are rearranged using F function and K2:
    F1 = F(right, K2)
    # XOR with left 4 bits:
    right2 = left ^ F1
    # left 4 bits are rearranged using F function and K1:
    F2 = F(right2, K1)
    # XOR with right 4 bits:
    left2 = F2 ^ right
    # combine into an 8-bit number:
    combo = (left2 << 4) + right2
    # use inverse initial permutation (FP) on comb to get 8-bit cypher text:
    P = 0
    for i in FP:
        P = P << 1
        if getIthBit(combo, 8, i) != 0:
            P += 1
    return P

# encrpyts list of bytes one at a time    
def encrypt(P, K):
    T = []
    for b in P:
        T.append(encryptByte(b, K))
    return T

# decrypts list of bytes one at a time
def decrypt(T, K):
    P = []
    for b in T:
        P.append(decryptByte(b, K))
    return P

# Permutation Arrays:
IP = [2, 6, 3, 1, 4, 8, 5, 7]
FP = [4, 1, 3, 5, 7, 2, 8, 6]
PC1 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
PC2 = [6, 3, 7, 4, 8, 5, 10, 9]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

# Substitution Matrices:
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

# Running Encryption and Decryption with sample plaintext
print("Simplified DES:\n")
key = 0b1100011110
print("Key:\t\t{:010b}".format(key))
P = [0b01100011, 0b01110010, 0b01111001, 0b01110000, 0b01110100, 0b01101111]
print("Plaintext:\t", end = "")
for b in P:
    print("{:08b}".format(b), end = " ")
print("\n")
T = encrypt(P, key)
print("Encryption:\t", end = "")
for b in T:
    print("{:08b}".format(b), end = " ")
print()
P2 = decrypt(T, key)
print("Decryption:\t", end = "")
for b in P2:
    print("{:08b}".format(b), end = " ")
print()


