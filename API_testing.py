import os
import requests
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get API key from environment variable
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def upload_file(file_path):
    try:
        url = 'https://www.virustotal.com/api/v3/files'
        headers = {'x-apikey': API_KEY}

        with open(file_path, 'rb') as f:
            file = f.read()
            files = {'file': file}
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()  # Raise exception for bad status codes
        
        print("@"*100)
        print(response.json())
        print("@"*100)

        return response.json()['data']['id']
    except requests.exceptions.RequestException as e:
        print(f'Error: {e}')
        return None

def check_scan_status(scan_id):
    try:
        url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
        headers = {'x-apikey': API_KEY}

        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise exception for bad status codes

        print("#"*100)
        print(response.json())
        print("#"*100)

        # return response.json()['data']['attributes']['status']
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f'Error: {e}')
        return None

def get_file_report(scan_id):
    try:
        url = f'https://www.virustotal.com/api/v3/files/{scan_id}'
        headers = {'x-apikey': API_KEY}

        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise exception for bad status codes

        return response.json()
    except requests.exceptions.RequestException as e:
        print(f'Error: {e}')
        return None

if __name__ == "__main__":
    file_path = input("Enter the path to the file: ")

    # Step 1: Upload the file
    print("Uploading the file for scanning...")
    scan_id = upload_file(file_path)

    if scan_id:
        print(f"File uploaded successfully. Scan ID: {scan_id}")

        # Step 2: Check the scan status
        while True:
            print("Checking scan status...")
            result = check_scan_status(scan_id)
            status = result['data']['attributes']['status']
            if status == 'completed':
                print("Scan completed.")
                break
            elif status == 'queued' or status == 'in_progress':
                print("Scan in progress. Waiting for 10 seconds before checking again...")
                time.sleep(10)
            else:
                print(f"Scan failed with status: {status}")
                break

        # Step 3: Retrieve the file report
        print("Retrieving file report...")
        sha256 = result['meta']['file_info']['sha256']
        file_report = get_file_report(sha256)

        if file_report:
            print("File Report:")
            print(file_report)
