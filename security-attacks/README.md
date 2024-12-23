# Security Attacks on SecureSnap

To run these security attack scripts:

Create a virtual environment and activate it
`python3 -m venv venv && source venv/bin/activate`

`pip install .`

To sniff the packets coming from server response and retrieve the access token, run `sniff_server_response.py`. This would do the sniffing part and then use the retrieved access token to acess protected API endpoint hence compromising security.

To sniff the packets going as a request from client and retrieve the access token from the authorization header, run `sniff_client_request.py`. This would do the sniffing part and then use the retrieved access token to acess protected API endpoint hence compromising security.

This is the attack on the first part of token-based authentication (without encryption). Encrypting the access token would prevent such as attack because even if the sniffer gets hold of access token, they can not decrypt the token to make the valid authorized request to the server. Hence adding encryption would ensure confidentiality in the system.


# Generate self-signed certificate

```
sudo apt install openssl

mkdir certs && cd certs

openssl genrsa -des3 -out self_signed_CA.key 2048

openssl req -x509 -new -nodes -key self_signed_CA.key -sha256 -days 1825 -out self_signed_CA.pem
```