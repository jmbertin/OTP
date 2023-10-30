# OTP - One-Time Password Generator

`otp` is a command-line utility to securely store an initial password (in hexadecimal format) and generate one-time passwords based on the HOTP algorithm.

----

## Requirements

- Python 3
- Some dependancies:
  ``pip install -r requirements.txt``

----

## Usage

### Graphical User Interface (GUI)

The otp utility also provides a graphical interface for ease of use, especially for users who might not be comfortable using the command line.

**How to Use the GUI:**

- **Launching the GUI**

``python3 otp.py --graphic``

This command initializes a window that provides input fields and buttons to interact with the OTP generation process.

- **Storing the Initial Key via GUI**

Inside the launched window, there's a labeled input field that prompts users to "Enter the hexadecimal key."
After entering a valid hexadecimal key, users can click on the "Generate & Save Key" button. This will securely store the key and display the QR code for the key.

- **Generating a One-Time Password via GUI:**

Once a key has been stored, users can click the "Generate OTP" button.
The one-time password will then appear in large digits within the same window.

- **QR Code Display:**

When storing the initial key via the GUI, a QR code is also generated and displayed in a new window. This QR code can be scanned using OTP authentication apps, allowing for the quick addition of the key to such applications.
You can add it to your favorite OTP manager (tested functional with Google Authenticator) to compare the OTP provided by otp and your manager.


### Command line interface (CLI)

**Store the Initial Key**

To securely store the initial key:

``python3 otp.py -g <64_character_hexadecimal_key>``

*Here are some keys examples:*

````
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f01234
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef
deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
faceb00cfaceb00cfaceb00cfaceb00cfaceb00cfaceb00cfaceb00cfaceb00c
````

**Generate a One-Time Password**

To generate a new one-time password based on the stored key:

``python3 otp.py -k``

**QR-Code**
You can open the QR code contained in the otp seed.png file and add it to your favorite OTP manager (tested functional with Google Authenticator) to compare the OTP provided by otp and your manager.

**For additional help:**

``python3 otp.py -h``

----

## Implementation Details

**The HOTP algorithm (RFC 4226) is used for generating the OTP.**

**Generated OTPs are always 6 digits long.**

**Two separate files are used to store different information:**

**otp.key**: This file stores the HOTP key once it has been encrypted. The HOTP key is the secret key used to generate OTPs. Before being stored, this key is encrypted to protect it. Once encrypted, the key can only be decrypted and used if you have the appropriate encryption key.

**otp.cip**: This file stores the encryption key (or encryption key) used by the encryption algorithm (in this case, Fernet). This key is essential for decrypting the HOTP key stored in otp.key.

The reason these two keys are stored separately is to add an **extra layer of security**. Even if someone manages to access the otp.key file and extract the encrypted key, that key would be unusable without the encryption key stored in otp.cip.

By keeping these two elements separate, it's more difficult for anyone trying to illegally access the secret key. They would need to obtain both the encrypted key and the encryption key to reproduce the OTP.

----

### HOTP Algorithm Explained

**What is HOTP?**
HOTP stands for HMAC-based One-Time Password. It's an algorithm that produces a one-time password by combining a secret key with a counter value. HMAC (Hash-based Message Authentication Code) is used as a core component of this algorithm.

**Components:**
- **Shared Secret (K):** A secret value that is shared between the server and the client/token. This is usually generated when the token is provisioned.
Counter (C): A counter value that is incremented every time a new OTP is generated. Both server and client/token maintain a synchronized counter.

**Process:**
- **Combination:** The algorithm takes the shared secret and the counter as inputs.
- **HMAC Calculation:** Using the HMAC algorithm with SHA-1 (by default), it computes a hash of the combined secret and counter.
- **Truncation:** The computed HMAC is truncated to produce a shorter value. This involves:
Taking the last 4 bits of the HMAC as an offset, offset.
Considering the 4 bytes starting at the offset from the HMAC and discarding the most significant bit. This leaves a 31-bit number.
The final OTP value is taken by considering the last d digits of the resulting number (where d is the desired length of the OTP, usually 6 or 8 digits).
- **Display:** The OTP is finally displayed or transmitted for authentication.


**Security:**

- The OTP's security arises from the HMAC-SHA1 computation, which is hard to reverse, meaning it's not feasible to derive the original inputs from the output.
- The shared secret should remain confidential. If it's compromised, the generated OTPs will be predictable.
- The OTP's short length and truncation make it resistant to brute-force attacks, especially since they're valid for a limited time or limited use.

*Differences from TOTP:*
HOTP and TOTP (Time-based One-Time Password) are closely related, but while HOTP uses a counter to generate unique OTPs, TOTP uses the current time.

**Applications:**
HOTP is often used in hardware tokens, authentication apps, and systems where two-factor authentication is desired.

**Notes:**
If the counter on the client/token and server become out of sync, they might produce different OTPs. Some systems account for this by validating OTPs from a range of counter values.
HOTP is only one method for OTP generation. Other methods, like TOTP (which builds on HOTP by replacing the counter with a timestamp), are also widely used.

*References:*
[RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc4226)
