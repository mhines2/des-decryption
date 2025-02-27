#!/usr/bin/env python3
from Crypto.Cipher import DES
import binascii

# DES Tables and Permutations

PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
IP_1 = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
S = {
    1:[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
    [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
    [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
    [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],

    2:[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
    [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
    [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
    [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    
    3:[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
    [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
    [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
    [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    
    4:[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
    [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
    [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
    [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],

    5:[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
    [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
    [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
    [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],

    6:[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
    [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
    [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
    [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    
    7:[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
    [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
    [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
    [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],

    8:[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
    [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
    [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
    [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
    }

# Binary Operations

def bin_to_bytes(binary_str):
    """Convert a binary string to bytes."""
    byte_arr = int(binary_str, 2).to_bytes(len(binary_str) // 8, byteorder='big')
    return byte_arr

def left_shift(amount, key):
    """ Shifts the key to the left by the given amount."""
    return key[amount:] + key[:amount]

def permute(key_combined):
    """Permute the key using PC2."""
    return ''.join([key_combined[i - 1] for i in PC2])

def xor(bitstring1, bitstring2):
    """XOR two bitstrings."""
    return ''.join(str(int(a) ^ int(b)) for a, b in zip(bitstring1, bitstring2))

# Round Key Generation

def keygen(key):
    """Generates 16 subkeys from the given key."""
    permuted_key = ''.join([key[i - 1] for i in PC1]) # initial permutation
    half_length = len(permuted_key) // 2 # split key in half
    left_half = permuted_key[:half_length]
    right_half = permuted_key[half_length:]
    iterations = [[left_half, right_half]]
    subkeys = []

    # Generate 16 subkeys using left shift operation and PC2 permutation
    for round_number in range(16):
        shift_amount = SHIFT[round_number]
        previous_left, previous_right = iterations[-1] # get previous left and right halves
        shifted_left = left_shift(shift_amount, previous_left)
        shifted_right = left_shift(shift_amount, previous_right)
        iterations.append([shifted_left, shifted_right])
        combined_key = permute(shifted_left + shifted_right) # permute combined key
        subkeys.append(combined_key)
        print(f'K{round_number + 1:<2}: {combined_key}') 
    return subkeys

# Feistel Function

def f(right_half, subkey):
    """The Feistel function."""
    expanded_right = ''.join([right_half[i - 1] for i in E]) # expand right half
    xor_result = xor(expanded_right, subkey) # XOR with subkey
    groups = [xor_result[i:i+6] for i in range(0, 48, 6)] # split into 6-bit groups
    sbox_result = ""

    # Apply S-box substitution
    for num, group in enumerate(groups): 
        row = int(group[0] + group[-1], 2)
        col = int(group[1:-1], 2)
        sbox_value = S[num + 1][row][col]
        sbox_result += bin(sbox_value)[2:].zfill(4)
    return ''.join([sbox_result[i - 1] for i in P])

# DES Decryption using Cipher Library

def des_decrypt(cipher_bin, key_bin):
    """Decrypts a 64-bit ciphertext using DES with a given 64-bit key."""
    
    # Convert binary strings to byte format
    cipher_bytes = bin_to_bytes(cipher_bin)
    key_bytes = bin_to_bytes(key_bin)
    
    # Create DES cipher object in ECB mode 
    des = DES.new(key_bytes, DES.MODE_ECB)
    
    # Decrypt message
    decrypted_bytes = des.decrypt(cipher_bytes)
    
    # Convert to readable ASCII text
    plaintext = decrypted_bytes.decode('utf-8', errors='ignore')
    
    return plaintext

def main():
    # Given encrypted text and key in binary format
    encrypted_text = "1100101011101101101000100110010101011111101101110011100001110011"
    key = "0100110001001111010101100100010101000011010100110100111001000100"

    # Generate 16 round keys
    print('Generated Round Keys:')
    subkeys = keygen(key)
    permuted_text = ''.join([encrypted_text[i - 1] for i in IP]) 
    half_length = len(permuted_text) // 2
    left_half = permuted_text[:half_length]
    right_half = permuted_text[half_length:]

    # Perform 16 rounds of DES Decryption
    print('\nLnRn (1<=n<=16):')
    for round_number in range(16):
        subkey = subkeys.pop() # get subkey
        new_left_half = right_half # swap left and right halves
        f_result = f(right_half, subkey) # apply Feistel function
        new_right_half = xor(left_half, f_result) # XOR with left half

        # Display round results
        print(f'L{round_number+1}: {new_left_half}')
        print(f'R{round_number+1}: {new_right_half}')
        print(f'f(R{round_number}, K{round_number+1}): {f_result}\n')
        
        # Update left and right halves
        left_half = new_left_half
        right_half = new_right_half
    
    # Combine left and right halves and perform final permutation
    combined_halves = right_half + left_half
    final_permutation = ''.join([combined_halves[i - 1] for i in IP_1])
    
    # Display decrypted text
    print('Decrypted Text in Binary:')
    print(final_permutation)
    print('\nDecrypted Text in ASCII:')
    deciphered_text = ''.join(chr(int(final_permutation[i:i+8], 2)) for i in range(0, len(final_permutation), 8))
    print(deciphered_text)

    # Perform DES Decryption with Cipher Library (to verify)
    plaintext = des_decrypt(encrypted_text, key)
    print("\nDecrypted Text using Cipher Library:", plaintext)

if __name__ == '__main__':
    main()