# Homework 1.a ==> Simplified DES
# performs a left shift on n, wrapping the last bit around to the front
# assumes n is 5 bits
import binascii

def circularShift28(n,m):
    n2 = (n << 1) & 0b1111111111111111111111111111
    # 5th bit was a 1 - add 1 to n2
    if n > 0b0111111111111111111111111111:
        n2 += 1
    if(m == 1):
        return n2
    else:
        return circularShift28(n2,m-1)


# returns the value of the ith bit from left (1 or 0):
def getIthBit(n, l, i):
    bit = n & (1 << (l - i))
    return bit >> (l - i)


def permute(arr, K, L):
    out = 0
    for a in arr:
        for b in a:
            out += getIthBit(K, L, b)
            out = out << 1
    return out >> 1


def ipermute(arr, K, L):
    out = 0
    i = 1
    for a in arr:
        for b in a:
            out += (getIthBit(K, L, i) << (L - b))
            i += 1
    return out


def CandD():
    return 0


def substitutes(n, Sa):
    row = 0
    row += getIthBit(n, 6, 1)
    row = row << 1
    row += getIthBit(n, 6, 6)
    col = 0
    col += getIthBit(n, 6, 2)
    col = col << 1
    col += getIthBit(n, 6, 3)
    col = col << 1
    col += getIthBit(n, 6, 4)
    col = col << 1
    col += getIthBit(n, 6, 5)
    return Sa[row][col]


def F48(R, K):
    out = 0b0000
    tmp = K ^ R
    last = 0b000000
    for a in range(8):
        this = tmp >> (42 - a*6)
        out += substitutes(this - last, S[a])
        out = out << 4
        last += (this - last)
        last = last << 6
    return permute(P, out >> 4, 32)


def IPLR(L, R, K, E):
    # Returns value of R(n) (L(n) is just R(n-1)
    out = L ^ F48(permute(E, R, 32), K)
    return out


def IPcalc(Keys):
    IP = permute(IParr, M, 64)
    #print("IP = {:064b}".format(IP), sep='')
    IPleft = IP >> 32
    IPright = IP & 0b11111111111111111111111111111111
    num = 0
    print()
    for k in Keys:
        num += 1
        l = IPright
        r = IPLR(IPleft, IPright, k, E)
        IPright = r
        IPleft = l
        #print("R", num, " = {:032b}".format(r), sep='')
    return ((IPright << 32) + IPleft)


def iIPcalc(Keys):
    IP = permute(IParr, M, 64)
    #print("IP = {:064b}".format(IP), sep='')
    IPright = IP & 0b11111111111111111111111111111111
    IPleft = IP >> 32
    num = 0
    #print()
    for k in reversed(Keys):
        num += 1
        l = IPright
        r = IPLR(IPleft, IPright, k, E)
        IPright = r
        IPleft = l
        #print("R", num, " = {:032b}".format(r), sep='')
    return ((IPright << 32) + IPleft)


def Kpluz(KpluZ):
    left = Kplus >> 28
    right = Kplus & 0b1111111111111111111111111111
    i = 0
    #print("C", i, " = {:028b}".format(left), sep='')
    #print("D", i, " = {:028b}".format(right), sep='')  # if 0 is at the beginning of it it will appear as shorter than it should
    #print()
    Iterations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    Keys = []
    i = 0
    for a in Iterations:
        i += 1
        left = circularShift28(left, a)
        right = circularShift28(right, a)
        #print("C", i, " = {:028b}".format(left), sep='')
        #print("D", i, " = {:028b}".format(right), sep='')
        k = permute(PC2, ((left << 28) + right), 56)
        #print("K", i, " = {:048b}".format(k), sep='')
        Keys.append(k)
        #print()
    return Keys

# Permutation Arrays:
S = []
S0 = [  [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]
S.append(S0)
S1 = [  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]
S.append(S1)
S2 = [  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]
S.append(S2)
S3 = [  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]
S.append(S3)
S4 = [  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]
S.append(S4)
S5 = [  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]
S.append(S5)
S6 = [  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]
S.append(S6)
S7 = [  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
S.append(S7)
IParr = [  [58, 50, 42, 34, 26, 18, 10, 2],
        [60, 52, 44, 36, 28, 20, 12, 4],
        [62, 54, 46, 38, 30, 22, 14, 6],
        [64, 56, 48, 40, 32, 24, 16, 8],
        [57, 49, 41, 33, 25, 17, 9, 1],
        [59, 51, 43, 35, 27, 19, 11, 3],
        [61, 53, 45, 37, 29, 21, 13, 5],
        [63, 55, 47, 39, 31, 23, 15, 7]]
P = [   [16, 7, 20, 21],
        [29, 12, 28, 17],
        [1, 15, 23, 26],
        [5, 18, 31, 10],
        [2, 8, 24, 14],
        [32, 27, 3, 9],
        [19, 13, 30, 6],
        [22, 11, 4, 25]]
IPinverse = [  [40, 8, 48, 16, 56, 24, 64, 32],
        [39, 7, 47, 15, 55, 23, 63, 31],
        [38, 6, 46, 14, 54, 22, 62, 30],
        [37, 5, 45, 13, 53, 21, 61, 29],
        [36, 4, 44, 12, 52, 20, 60, 28],
        [35, 3, 43, 11, 51, 19, 59, 27],
        [34, 2, 42, 10, 50, 18, 58, 26],
        [33, 1, 41, 9, 49, 17, 57, 25]]

FP = [4, 1, 3, 5, 7, 2, 8, 6]
# PC1 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
PC2 = [6, 3, 7, 4, 8, 5, 10, 9]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

PC1 = [ [57, 49, 41, 33, 25, 17, 9],
        [1, 58, 50, 42, 34, 26, 18],
        [10, 2, 59, 51, 43, 35, 27],
        [19, 11, 3, 60, 52, 44, 36],
        [63, 55, 47, 39, 31, 23, 15],
        [7, 62, 54, 46, 38, 30, 22],
        [14, 6, 61, 53, 45, 37, 29],
        [21, 13, 5, 28, 20, 12, 4]]
PC2 = [ [14, 17, 11, 24, 1, 5],
        [3, 28, 15, 6, 21, 10],
        [23, 19, 12, 4, 26, 8],
        [16, 7, 27, 20, 13, 2],
        [41, 52, 31, 37, 47, 55],
        [30, 40, 51, 45, 33, 48],
        [44, 49, 39, 56, 34, 53],
        [46, 42, 50, 36, 29, 32]]

E = [   [32, 1, 2, 3, 4, 5],
        [4, 5, 6, 7, 8, 9],
        [8, 9, 10, 11, 12, 13],
        [12, 13, 14, 15, 16, 17],
        [16, 17, 18, 19, 20, 21],
        [20, 21, 22, 23, 24, 25],
        [24, 25, 26, 27, 28, 29],
        [28, 29, 30, 31, 32, 1]]

message = "WeDidIt!"
MHex = ""
for c in message:
    MHex += format(ord(c), "x")

#MHex = hex("0123456789ABCDEF")
#M = 0b0000000100100011010001010110011110001001101010111100110111101111
M = int(MHex,16)
print("Message in binary = {:064b}".format(M), sep='')

# Substitution Matrices:
K = 0b0001001100110100010101110111100110011011101111001101111111110001
Kplus = permute(PC1, K, 64)
print("K+ = {:056b}".format(Kplus), sep='')
#Step 1
Keys = Kpluz(Kplus)
#Step 2
final = IPcalc(Keys)
print("before final permutation = {:064b}".format(final), sep='')
end = permute(IPinverse, final, 64)
print("encrypted in binary = {:064b}".format(end), sep='')
print("encrypted in hex = ", hex(end), sep='')

print()

M = end
print("Message in binary = {:064b}".format(M), sep='')
K = 0b0001001100110100010101110111100110011011101111001101111111110001
Kplus = permute(PC1, K, 64)
print("K+ = {:056b}".format(Kplus), sep='')
#Step 1
Keys = Kpluz(Kplus)
#Step 2
final = iIPcalc(Keys)
print("before final permutation = {:064b}".format(final), sep='')
end = permute(IPinverse, final, 64)
print("decrypted in binary = {:064b}".format(end), sep='')
print("decrypted in hex = ", hex(end), sep='')
print("Decrypted message = ", str(binascii.unhexlify(hex(end)[2:18]))[2:10], sep='')


# Running Encryption and Decryption with sample plaintext
"""
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
"""

