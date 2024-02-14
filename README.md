# Encryption
# Documentation:

# EncryptorAesGcm class
This class provides functionality for encrypting and decrypting data using the AES-GCM encryption algorithm. The encryption process uses a randomly generated IV and a 256-bit AES key. The IV is prepended to the encrypted data, and a MAC is appended to the end of the encrypted data. The MAC is used to verify the integrity of the decrypted data.

# Methods
encrypt(byte[] pText, SecretKey secret, byte[] iv)
Encrypts plaintext data using the AES-GCM encryption algorithm.

pText - the plaintext data to be encrypted
secret - the 256-bit AES key to use for encryption
iv - the IV to use for encryption
Returns: the encrypted data
decrypt(byte[] cText, SecretKey secret)
Decrypts ciphertext data using the AES-GCM encryption algorithm.

cText - the ciphertext data to be decrypted
secret - the 256-bit AES key to use for decryption
Returns: the decrypted data



