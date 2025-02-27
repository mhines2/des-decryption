# DES Decryption Program

This program decrypts a **64-bit DES-encrypted ciphertext** using a provided **64-bit key** in binary format. It follows the **Data Encryption Standard (DES) decryption process**, including:

- **Key Scheduling**: Generates 16 round keys using left circular shifts and permutations.
- **Feistel Function (f function)**: Performs 16 rounds of DES decryption, including expansion, substitution (S-boxes), permutation, and XOR operations.
- **Initial and Final Permutations**: Applies bitwise transformations to ensure proper decryption.
- **DES Cipher Library Support**: Uses the `pycryptodome` library to validate the decryption results.

## Usage
To run the program, ensure you have Python installed and execute:
```sh
python3 des_decryption.py
```

## Requirements
Install dependencies using:
```sh
pip install -r requirements.txt
```

## About
This program was created for my **Computer Security** course (**CSE 40567/60567**) as part of **HW2, Problem 6**. It includes both a manual implementation of DES decryption and verification using the `pycryptodome` library.

## Files
- `des_decryption.py` - The main decryption script.
- `requirements.txt` - Lists required Python dependencies.
- `README.md` - This file, documenting the project.

## Author
Michael Hines
