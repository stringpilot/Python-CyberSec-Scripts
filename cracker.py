import hashlib
import argparse
import os

class HashConverter:
    def __init__(self, passwordHashFileName, wordlistFileName):
        self.passwordHashFileName = passwordHashFileName
        self.wordlistFileName = wordlistFileName

    def hash_strings(self, EncodedByteStringToHash):
        hashAlgo = hashlib.md5(EncodedByteStringToHash)
        return hashAlgo.hexdigest()

    def crack(self):
        passwordHashlist = []

        with open(self.passwordHashFileName, 'rb') as passwordHashFile:
            for passwHash in passwordHashFile:
                passwordHashlist.append(passwHash.rstrip().decode())

        with open(self.wordlistFileName, 'rb') as wordlistFile:
            for bEncodedWord in wordlistFile:
                bEncodedWord = bEncodedWord.rstrip()
                EntryHash = self.hash_strings(bEncodedWord)

                with open(self.passwordHashFileName, 'rb') as hashedPasswordFile:
                    for hashed_password_entry in hashedPasswordFile:
                        if EntryHash == hashed_password_entry.rstrip().decode():
                            print("Password is:", bEncodedWord.decode(), "for Hash:", hashed_password_entry.decode())


        if len(passwordHashlist) > 0:
            for unidentified in passwordHashlist:
                print("No password found:", unidentified)

#Requires a /file-text-md5/txt and wordlist for bruteforcing
a1 = HashConverter("password-hashes.txt", "rockyou.txt")
a1.crack()
