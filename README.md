# DES Decryption Program

This program decrypts a **64-bit DES-encrypted ciphertext** using a provided **64-bit key** in binary format. It follows the **Data Encryption Standard (DES) decryption process**, including:

- **Key scheduling**: Generating 16 round keys.
- **Feistel function**: Performing 16 rounds of decryption.
- **Initial and inverse permutations**: Ensuring correct bit transformations.

## Usage
To run the program, ensure you have Python installed and execute:
```sh
python3 des-decryption.py
```

## Requirements
Install dependencies using:
```sh
pip install -r requirements.txt
```

## About
This program was created for my **Computer Security** course (**CSE 40567/60567**) as part of **HW2, Problem 6**.

## Files
- `des-decryption.py` - The main decryption script.
- `requirements.txt` - Lists required Python dependencies.
- `.gitignore` - Specifies files to exclude from version control.
- `README.md` - This file, documenting the project.

## Author
Michael Hines
