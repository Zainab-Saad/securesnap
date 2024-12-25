import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os

# Step 1: Fetch the server's public key
response = requests.get('http://localhost:6868/public-key')
if response.status_code != 200:
    print("Failed to fetch the public key from the server.")
    exit(1)

server_response = response.json()
if not server_response['success']:
    print("Server responded with an error:", server_response['message'])
    exit(1)

# Extract the public key from the response
server_public_key_pem = server_response['data']['publicKey']

# Step 2: Load the server's public key
try:
    server_public_key = serialization.load_pem_public_key(
        server_public_key_pem.encode(),
    )
except Exception as e:
    print("Failed to load the server's public key:", str(e))
    exit(1)

# Step 3: Generate a symmetric key (AES)
symmetric_key = os.urandom(32)  # 256-bit key
print(f'Generated Symmetric Key: {symmetric_key.hex()}')

# Store the symmetric key in a file (Hex-encoded)
with open('/home/zainab/Documents/NUST/Semester 7/Information Security sem 7/Project/client/symmetric_key_client.txt', 'w') as file:
    file.write(symmetric_key.hex())
print('Symmetric key saved to symmetric_key_client.txt')

# Step 4: Encrypt the symmetric key using the server's public key
try:
    encrypted_key = server_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
except Exception as e:
    print("Failed to encrypt the symmetric key:", str(e))
    exit(1)

# Base64 encode the encrypted key for transmission
encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')
print("Client generated Symmetric key encrypted with the server's public key is:", encrypted_key_b64)

# Step 5: Send the encrypted key to the server
exchange_response = requests.post(
    'http://localhost:6868/exchange-key',
    json={'encryptedKey': encrypted_key_b64}
)

if exchange_response.status_code == 200:
    print("Encrypted key successfully sent to the server!")
    print("Server response:", exchange_response.text)
else:
    print("Failed to exchange the key. Server response:")
    print(exchange_response.text)
