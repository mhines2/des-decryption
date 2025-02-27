#!/usr/bin/env python3
from Crypto.Cipher import DES
import binascii

def bin_to_bytes(binary_str):
    """Convert a binary string to bytes."""
    byte_arr = int(binary_str, 2).to_bytes(len(binary_str) // 8, byteorder='big')
    return byte_arr

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

# Given Ciphertext and Key in Binary Format
ciphertext_bin = "1100101011101101101000100110010101011111101101110011100001110011"
key_bin = "0100110001001111010101100100010101000011010100110100111001000100"

# Perform DES Decryption
plaintext = des_decrypt(ciphertext_bin, key_bin)
print("Decrypted Text:", plaintext)
