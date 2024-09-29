from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, logout, login
from django.contrib import messages
from django.core.files.storage import default_storage
import os
from django.conf import settings
import requests
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get API key from environment variable
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

# Create your views here.
def index(request):
    if request.user.is_anonymous:
        return redirect("/login")
    return render(request, 'index.html')

def loginUser(request):
    if request.method == "POST":

        username=request.POST.get('username')
        password=request.POST.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("/")
        else:
             messages.error(request, "Invalid Username OR Password!!!")
             return render(request, 'login.html')
    return render(request, "login.html")

def logoutUser(request):
    logout(request)
    return redirect("/login")

def upload(request):
    if request.method == 'POST' and request.FILES['file']:
        uploaded_file = request.FILES['file']

        filename = uploaded_file.name

        # Send file to storage container
        response = send_file_to_storage_container(uploaded_file, filename)
        
        # Process response
        if response.status_code == 200:
            messages.success(request, f'File uploaded successfully.')
            return render(request, "dashboard.html")
        else:
            messages.success(request, f'File Not Uploaded!!!')
            return render(request, "index.html")
    else:
        messages.error(request, f'File upload Error!!!')
        return render(request, "index.html")


    return render(request, 'index.html')

def send_file_to_storage_container(file, name):
    # Define storage container's URL
    storage_container_url = 'http://172.18.0.2:9000'

    # Send file to storage container
    files = {'file': file}

    headers = {'Content-Disposition': f'attachment; filename="{name}"'}

    response = requests.post(storage_container_url, files=files, headers=headers)

    return response

def get_file_from_storage_container(file_name):
    file_url = f"http://172.18.0.2:9000/app/malware/{file_name}"

    # Send a GET request to the server
    response = requests.get(file_url)

    if response.status_code == 200:        
        return response.content
    else:
        ret = f"Failed to download file. Status code: {response.status_code}"
        return ret.encode('utf-8')

def upload_file(file):
    try:
        url = 'https://www.virustotal.com/api/v3/files'
        headers = {'x-apikey': API_KEY}

        files = {'file': file}
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()  # Raise exception for bad status codes

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
        return None

def dashboard(request):
    file_name = None
    if request.method == 'POST':
        file_name = request.POST.get('getfile')

    requested_file = get_file_from_storage_container(file_name)

    if b"Failed to download file. Status code:" not in requested_file:
        scan_id = upload_file(requested_file)

        if scan_id:
            while True:
                result = check_scan_status(scan_id)
                status = result['data']['attributes']['status']
                if status == 'completed':
                    break
                elif status == 'queued' or status == 'in_progress':
                    time.sleep(10)
                else:
                    return render(request, 'dashboard.html', {'file_name': file_name, 'scan_fail': status})

            sha256 = result['meta']['file_info']['sha256']
            file_report = get_file_report(sha256)

            info = {"suspicious":[],
            "undetected":[],
            "harmless":[],
            "timeout":[],
            "confirmed-timeout":[],
            "failure":[],
            "type-unsupported":[]}

            if file_report:
                for key, value in file_report["data"]["attributes"]["last_analysis_results"].items():
                    if value["category"] == "undetected":
                        info["undetected"].append(key)
                    elif value["category"] == "suspicious":
                        info["suspicious"].append(key)
                    elif value["category"] == "harmless":
                        info["harmless"].append(key)
                    elif value["category"] == "timeout":
                        info["timeout"].append(key)
                    elif value["category"] == "confirmed-timeout":
                        info["confirmed-timeout"].append(key)
                    elif value["category"] == "failure":
                        info["failure"].append(key)
                    elif value["category"] == "type-unsupported":
                        info["type-unsupported"].append(key)
                    else:
                        pass

                return render(request, 'report.html', {'file_name': file_name, 'file_hash': sha256, 'file_report': file_report, 'info': info})
    else:
        return render(request, 'dashboard.html', {'file_name': file_name, 'no_file': 'FILE DIES NOT EXISTS ON SERVER...'})

                
    return render(request, 'dashboard.html', {'file_name': file_name})