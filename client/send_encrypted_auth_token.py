from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from get_encrypted_server_response import get_decrypted_response
import requests
import os
import json

# Helper function to encrypt data using symmetric key
def encrypt_data(symmetric_key, plaintext):
    """
    Encrypts the given plaintext using the symmetric key.

    Args:
        symmetric_key (bytes): Symmetric key for encryption.
        plaintext (str): The plaintext to encrypt.

    Returns:
        tuple: A tuple containing the encrypted data and the IV.
    """
    try:
        # Generate a new IV for encryption
        iv = os.urandom(16)

        # Set up the AES cipher with CBC mode
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Add PKCS7 padding to the plaintext
        padder = PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        # Encrypt the padded plaintext
        encrypted_data = encryptor.update(padded_plaintext) + encryptor.finalize()
        return encrypted_data, iv
    except Exception as e:
        raise ValueError(f"Error during encryption: {e}")

# Symmetric key file and login details
symmetric_key_file = "/home/zainab/Documents/NUST/Semester 7/Information Security sem 7/Project/client/symmetric_key_client.txt"
login_url = "http://localhost:6868/login"
login_payload = {
    "email": "zainab.saad567@gmail.com",  # Replace with your email
    "password": "zainab1234"      # Replace with your password
}

try:
    # Step 1: Get decrypted plaintext from login response
    decrypted_plaintext = get_decrypted_response(symmetric_key_file, login_url, login_payload)
    print("Final Decrypted Plaintext:", decrypted_plaintext)

    # Step 2: Extract access token and nonce from the plaintext
    decrypted_data = json.loads(decrypted_plaintext)
    access_token = decrypted_data['accessToken']
    nonce = decrypted_data['nonce']
    print(f"Access Token: {access_token}")
    print(f"Nonce: {nonce}")

    # Step 3: Encrypt the access token and nonce
    with open(symmetric_key_file, "r") as file:
        symmetric_key_hex = file.read().strip()
    symmetric_key = bytes.fromhex(symmetric_key_hex)

    combined_data = f"{access_token}:{nonce}"  # Combine token and nonce with a delimiter
    encrypted_data, iv = encrypt_data(symmetric_key, combined_data)
    print(f"Encrypted Data: {encrypted_data.hex()}")
    print(f"IV: {iv.hex()}")

    # Step 4: Send the encrypted data in the Authorization header to the /get-me endpoint
    get_me_url = "http://localhost:6868/get-me"
    headers = {
        "Authorization": f"Bearer {encrypted_data.hex()}",
        "IV": iv.hex(),
        "Content-Type": "application/json"
    }

    get_me_response = requests.get(get_me_url, headers=headers)
    get_me_response.raise_for_status()  # Raise an error if the request fails

    # Step 5: Process the server's response
    response_data = get_me_response.json()
    if not response_data.get("success", False):
        print(f"`/get-me` request failed: {response_data.get('message')}")
    else:
        print("`/get-me` Response:", json.dumps(response_data, indent=4))

except Exception as e:
    print(f"Error: {e}")
