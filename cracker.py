import hashlib
import argparse
import sys

class HashConverterMD5:
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

class HashConverterSHA512:
    def __init__(self, passwordHashFileName, wordlistFileName):
        self.passwordHashFileName = passwordHashFileName
        self.wordlistFileName = wordlistFileName

    def hash_string(self, EncodedByteStringToHash):
        hashAlgo = hashlib.sha512(EncodedByteStringToHash)
        return hashAlgo.hexdigest()

    def crack(self):
        passwordHashlist = []

        with open(self.passwordHashFileName, 'rb') as passwordHashFile:
            for passwHash in passwordHashFile:
                passwordHashlist.append(passwHash.rstrip().decode())

        with open(self.wordlistFileName, 'rb') as wordlistFile:
            for bEncodedWord in wordlistFile:
                bEncodedWord = bEncodedWord.rstrip()
                EntryHash = self.hash_string(bEncodedWord)

                with open(self.passwordHashFileName, 'rb') as hashedPasswordFile:
                    for hashed_password_entry in hashedPasswordFile:
                        if EntryHash == hashed_password_entry.rstrip().decode():
                            print("Password for SHA-512 is:", bEncodedWord.decode(), "Hash for SHA-512:", hashed_password_entry.decode())

class HashConverterSHA256:
    def __init__(self, passwordHashFileName, wordlistFileName):
        self.passwordHashFileName = passwordHashFileName
        self.wordlistFileName = wordlistFileName

    def hash_string(self, EncodedByteStringToHash):
        hashAlgo = hashlib.sha256(EncodedByteStringToHash)
        return hashAlgo.hexdigest()

    def crack(self):
        passwordHashlist = []

        with open(self.passwordHashFileName, 'rb') as passwordHashFile:
            for passwHash in passwordHashFile:
                passwordHashlist.append(passwHash.rstrip().decode())

        with open(self.wordlistFileName, 'rb') as wordlistFile:
            for bEncodedWord in wordlistFile:
                bEncodedWord = bEncodedWord.rstrip()
                EntryHash = self.hash_string(bEncodedWord)

                with open(self.passwordHashFileName, 'rb') as hashedPasswordFile:
                    for hashed_password_entry in hashedPasswordFile:
                        if EntryHash == hashed_password_entry.rstrip().decode():
                            print("Password for SHA-256 is:", bEncodedWord.decode(), "Hash for SHA-256:", hashed_password_entry.decode())

def main():
    parser = argparse.ArgumentParser(description='Password Cracker with MD5, SHA512, SHA256. Note there are no salt keys provided, and this program needs to be modified. Press -h for HELP')
    parser.add_argument('-w', '--wordlist', dest='wordlist', required=True, help='Wordlist file')
    parser.add_argument('-hf', '--hash-function', dest='hash_function', default='md5',
                        choices=['md5', 'sha512', 'sha256'], help='Hash function (md5, sha256 or sha512). EXAMPLE: -hf md5')
    parser.add_argument('-hs', '--hash-list',dest='hash_lists', help='Input hash file in here')
    args = parser.parse_args()

    if len(sys.argv) < 5:
        print ('Input is required')
        exit(0)

    if args.hash_function == 'md5':
        hash_converter = HashConverterMD5(args.hash_lists, args.wordlist)
    elif args.hash_function == 'sha512':
        hash_converter = HashConverterSHA512(args.hash_lists, args.wordlist)
    elif args.hash_function == 'sha256':
        hash_converter = HashConverterSHA256(args.hash_lists, args.wordlist)
    else:
        print("Invalid hash function")
        exit(1)

    hash_converter.crack()

if __name__ == '__main__':
    main()
