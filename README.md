# MVMZ-Crypter

![image](https://github.com/user-attachments/assets/7c56ba5e-5cc9-42c5-9049-32763b6f2dde)


RPG Maker MV/MZ File Utility

A simple and efficient tool for managing files used in RPG Maker MV and MZ.

<h2>Features</h2>

1. Key Extraction

Select the directory containing encrypted files to extract the encryption key.

The extracted key can also be used for decryption or re-encryption.

2. Decryption

Select a directory of encrypted files to decrypt in ``encrypted`` folder, and output them to the ``decrypted`` folder.

The encryption key is automatically detected and applied during this process—manual input is not required.

But if you want to decrypt folders containing audio files, you need to include an encrypted image or the system.json file into those folders.

3. Encryption

Select a directory of decrypted files to encrypt in ``decrypted`` folder, and output the results to the ``encrypted`` folder.

You will need to manually input the encryption key for this process.

4. Re-Encryption

Select a directory of encrypted files to decrypt in ``encrypted`` folder, and re-encrypt them with a new encryption key.

The re-encrypted files will be saved in the ``re-encrypted`` folder.

You will need to manually input the encryption key only for the re-encryption process.

When handling individual audio files, caution is required just as with decryption.

<h2>Supported File Types</h2>

This utility supports the following 10 file extensions:

``.rpgmvp``, ``.rpgmvm``, ``.rpgmvo``

``.png_``, ``.ogg_``, ``.m4a_``

``.png``, ``.ogg``, ``.m4a``, ``.json``

<h2>Additional Information</h2>

Inspired by Petschko's RPG-Maker MV & MZ-File Decrypter.

Developed with support from Claude 3.5 Sonnet.

The creator assumes no responsibility for any issues arising from the use of this utility.
