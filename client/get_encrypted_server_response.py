from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import requests
import json

def get_decrypted_response(symmetric_key_file, login_url, login_payload):
    """
    Retrieves and decrypts the server's encrypted response.

    Args:
        symmetric_key_file (str): Path to the symmetric key file.
        login_url (str): URL of the server's login endpoint.
        login_payload (dict): Payload containing login credentials.

    Returns:
        str: Decrypted plaintext data from the server response.
    """
    # Step 0: Load the symmetric key from the file
    try:
        with open(symmetric_key_file, "r") as file:
            symmetric_key_hex = file.read().strip()
        symmetric_key = bytes.fromhex(symmetric_key_hex)
        print(f"Symmetric Key Loaded: {symmetric_key.hex()}")
    except Exception as e:
        raise ValueError(f"Error reading symmetric key: {e}")

    # Step 1: Send a request to the server
    try:
        response = requests.post(login_url, json=login_payload)
        response.raise_for_status()  # Raise an error if the request fails
    except requests.RequestException as e:
        raise ConnectionError(f"Error connecting to the server: {e}")

    # Parse the JSON response
    try:
        server_response = response.json()
        if not server_response.get("success", False):
            raise ValueError(f"Login failed: {server_response.get('message')}")
        print("Login Successful! Processing the encrypted response...")
    except Exception as e:
        raise ValueError(f"Error parsing server response: {e}")

    # Step 2: Retrieve the `iv` and `encryptedData` from the response
    try:
        iv = bytes.fromhex(server_response['data']['iv'])
        encrypted_data = bytes.fromhex(server_response['data']['encryptedData'])
        print(f"IV: {iv.hex()}")
        print(f"Encrypted Data: {encrypted_data.hex()}")
    except Exception as e:
        raise ValueError(f"Error processing response data: {e}")

    # Step 3: Set up the decryption
    try:
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Step 4: Remove padding using PKCS7
        padder = PKCS7(128).unpadder()
        unpadded_data = padder.update(decrypted_data) + padder.finalize()

        # Decode the plaintext
        plaintext = unpadded_data.decode('utf-8')
        print("Decrypted Data:", plaintext)
        return plaintext
    except Exception as e:
        raise ValueError(f"Error during decryption: {e}")

symmetric_key_file = "/home/zainab/Documents/NUST/Semester 7/Information Security sem 7/Project/client/symmetric_key_client.txt"
login_url = "http://localhost:6868/login"
login_payload = {
    "email": "zainab.saad567@gmail.com",  # Replace with your email
    "password": "zainab1234"      # Replace with your password
}

try:
    decrypted_plaintext = get_decrypted_response(symmetric_key_file, login_url, login_payload)
    print("Final Decrypted Plaintext:", decrypted_plaintext)
except Exception as e:
    print(f"Error: {e}")
