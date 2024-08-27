import os
import json
import logging
import smtplib
import requests
import pdfkit
import dash
import dash_core_components as dcc
import dash_html_components as html
import pandas as pd
import plotly.express as px
from email.mime.text import MIMEText
from tkinter import Tk, filedialog
from PIL import Image, ImageGrab
import pytesseract
from configparser import ConfigParser
import webbrowser
import subprocess
import shutil
import threading

# Function to print VORTEX banner
def print_banner():
    banner = """
 ___      ___  ______     _______  ___________  _______  ___  ___  
|"  \    /"  |/    " \   /"      \("     _   ")/"     "||"  \/"  | 
 \   \  //  /// ____  \ |:        |)__/  \\__/(: ______) \   \  /  
  \\  \/. .//  /    ) :)|_____/   )   \\_ /    \/    |    \\  \/   
   \.    //(: (____/ //  //      /    |.  |    // ___)_   /\.  \   
    \\   /  \        /  |:  __   \    \:  |   (:      "| /  \   \  
     \__/    \"_____/   |__|  \___)    \__|    \_______)|___/\___| 
                                                                   
    """
    print(banner)

# Function to print usage instructions
def print_usage_instructions():
    print("""
    VORTEX Pentesting Tool Usage Instructions:
    1. **Setup Configuration Files:**
       - Ensure you have 'config.ini' with the required API keys and URLs.
       - Ensure you have 'smtp.ini' with SMTP server configuration.
    2. **Prepare IP/Domain List:**
       - Create 'iplist.txt' with domains or emails, separated by commas.
    3. **Run the Script:**
       - Execute the script: python vortex.py
    4. **Project Directory:**
       - Enter a project name when prompted. A directory with this name will be created.
    5. **Accessing the GUI:**
       - The GUI uses `tkinter` for file operations. It will prompt you to select files or directories if needed.
    6. **Accessing the Dash Dashboard:**
       - After running the script, the dashboard will be available at http://127.0.0.1:8050/.
    7. **Output Files:**
       - Results and reports will be saved in the project directory.
    8. **Email Notifications:**
       - If SMTP credentials are updated, email notifications will be sent.
    9. **Important Notes:**
       - Ensure all required tools are installed and accessible in your PATH.
    """)

# Function to check for the latest version on GitHub
def check_version(github_repo_url, local_version):
    try:
        # Fetch the latest version from GitHub
        response = requests.get(f"{github_repo_url}/raw/main/version.txt")
        response.raise_for_status()
        latest_version = response.text.strip()
        
        if local_version != latest_version:
            print(f"A new version {latest_version} is available. Please update the script.")
        else:
            print("You are using the latest version.")
    except Exception as e:
        print(f"Error checking for updates: {e}")

# Function to check and install dependencies
def install_dependencies():
    try:
        import subprocess
        dependencies = ['nmap', 'nikto', 'recon-ng', 'zap-cli', 'ssh-audit', 'nuclei']
        for dep in dependencies:
            if subprocess.call(['which', dep], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
                print(f"{dep} is not installed. Installing...")
                subprocess.call(['sudo', 'apt-get', 'install', '-y', dep])
    except Exception as e:
        logging.error(f"Error installing dependencies: {e}")
        print(f"Error installing dependencies: {e}")

# Function to check for required tools
def check_tools():
    tools = ['nmap', 'nikto', 'recon-ng', 'zap-cli', 'ssh-audit', 'nuclei']
    for tool in tools:
        if not shutil.which(tool):
            logging.error(f"Required tool {tool} is not installed.")
            print(f"Required tool {tool} is not installed. Please install it before running the script.")
            exit(1)

# Function to create default files if they don't exist
def create_default_files():
    files = {
        'config.ini': """
[Dehashed]
api_key = YOUR_DEHASHED_API_KEY
user_email = YOUR_EMAIL

[GraphRunner]
api_url = YOUR_GRAPH_RUNNER_API_URL

[SSH Audit]
api_key = YOUR_SSH_AUDIT_API_KEY
        """,
        'smtp.ini': """
[SMTP]
server = smtp.example.com
port = 587
username = your_username
password = your_password
from = your_email@example.com
        """,
        'iplist.txt': """
# Add your IP addresses or domains here, separated by commas.
        """
    }
    for filename, content in files.items():
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                f.write(content)
            print(f"{filename} created with example data.")

# Function to load configuration
def load_config(filename):
    config = ConfigParser()
    config.read(filename)
    return config

# Function to create project directory
def create_project_directory(project_name):
    project_dir = f'./{project_name}'
    os.makedirs(project_dir, exist_ok=True)
    return project_dir

# Function to check IP list
def check_ip_list(filename):
    if not os.path.exists(filename):
        print(f"{filename} not found. Please create it with a list of IPs or domains.")
        exit(1)
    
    with open(filename, 'r') as f:
        content = f.read().strip()
    
    if not content:
        print(f"{filename} is blank. Please add IPs or domains.")
        exit(1)
    
    # Handle comma-separated IPs and URLs with http:// or https://
    items = [item.strip().replace('http://', '').replace('https://', '') for item in content.split(',')]
    return items

# Function to query Dehashed API
def query_dehashed(domain, api_key, user_email=None):
    try:
        url = f"https://dehashed.com/search?query={domain}"
        headers = {'Authorization': f'Bearer {api_key}'}
        if user_email:
            headers['User-Email'] = user_email
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"Error querying Dehashed: {e}")
        return f"Error querying Dehashed: {e}"

# Function to analyze graph data with GraphRunner
def analyze_graph(results, api_url):
    try:
        response = requests.post(api_url, json=results)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"Error analyzing graph: {e}")
        return f"Error analyzing graph: {e}"

# Function to audit SSH configuration with SSH Audit
def audit_ssh(ip, project_dir):
    try:
        logging.info(f"Auditing SSH configuration for {ip}")
        result = subprocess.check_output(['ssh-audit', ip])
        with open(f'{project_dir}/ssh_audit_{ip}.txt', 'w') as f:
            f.write(result.decode())
        return result.decode()
    except Exception as e:
        logging.error(f"Error auditing SSH configuration: {e}")
        return f"Error auditing SSH configuration: {e}"

# Function to run Nmap scan
def run_nmap(ip, project_dir):
    try:
        logging.info(f"Running Nmap scan for {ip}")
        result = subprocess.check_output(['nmap', '-A', ip])
        with open(f'{project_dir}/nmap_{ip}.txt', 'w') as f:
            f.write(result.decode())
        return result.decode()
    except Exception as e:
        logging.error(f"Error running Nmap scan: {e}")
        return f"Error running Nmap scan: {e}"

# Function to run Nikto scan
def run_nikto(ip, project_dir):
    try:
        logging.info(f"Running Nikto scan for {ip}")
        result = subprocess.check_output(['nikto', '-host', ip])
        with open(f'{project_dir}/nikto_{ip}.txt', 'w') as f:
            f.write(result.decode())
        return result.decode()
    except Exception as e:
        logging.error(f"Error running Nikto scan: {e}")
        return f"Error running Nikto scan: {e}"

# Function to run Recon-ng
def run_recon_ng(ip, project_dir):
    try:
        logging.info(f"Running Recon-ng for {ip}")
        result = subprocess.check_output(['recon-ng', '-r', ip])
        with open(f'{project_dir}/recon_ng_{ip}.txt', 'w') as f:
            f.write(result.decode())
        return result.decode()
    except Exception as e:
        logging.error(f"Error running Recon-ng: {e}")
        return f"Error running Recon-ng: {e}"

# Function to run OWASP ZAP
def run_owasp_zap(ip, project_dir):
    try:
        logging.info(f"Running OWASP ZAP for {ip}")
        result = subprocess.check_output(['zap-cli', 'scan', ip])
        with open(f'{project_dir}/owasp_zap_{ip}.html', 'w') as f:
            f.write(result.decode())
        return result.decode()
    except Exception as
