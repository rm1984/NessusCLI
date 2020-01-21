#!/usr/bin/env python3

#
# NessusCLI
# ---------
# Python script to handle Nessus scans from the command line (no APIs required).
#
# Coded by: Riccardo Mollo (riccardomollo84@gmail.com)
#

import argparse
import logging
import requests
import signal
import sys
import urllib3
from fake_useragent import UserAgent
from termcolor import colored

requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'
requests.packages.urllib3.contrib.pyopenssl.extract_from_urllib3()
urllib3.disable_warnings()

def signal_handler(s, frame):
    if s == 2: # SIGINT
        print('You pressed Ctrl+C!')
        print('Goodbye!')
        sys.exit()

def logo():
    print(colored('                   ', 'cyan'))
    print(colored('+-+-+-+-+-+-+-+-+-+', 'cyan'))
    print(colored('|N|e|s|s|u|s|C|L|I|', 'cyan'))
    print(colored('+-+-+-+-+-+-+-+-+-+', 'cyan'))
    print(colored('          Coded by: Riccardo Mollo', 'cyan'))
    print()

def get_token(url, username, password, verify):
    r = requests.post(url + '/session', json = {'username': username, 'password': password}, verify = verify)

    if 'token' in r.json():
        return r.json()['token']
    elif 'error' in r.json():
        print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' Error logging in: ' + colored(r.json()['error'], 'red'))
        sys.exit(1)
    else:
        print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' Unknown error during login. Exiting...')
        sys.exit(1)

def list_folders(url, token, verify):
    folders = requests.get(url + '/folders', headers = {'X-Cookie': 'token=' + token}, verify = verify).json()
    folder_names = []

    for folder in folders['folders']:
        folder_names.append(folder['name'])

    print('[+] Listing ' + str(len(folder_names)) + ' folders...')

    for folder in sorted(folder_names):
        print('[+]   ' + colored(folder, 'white', attrs = ['bold']))

def list_scans(folder, url, token, verify):
    folder_id = str(get_folder_id(folder, url, token, verify))
    scans = requests.get(url + '/scans', params = {'folder_id': folder_id}, headers = {'X-Cookie': 'token=' + token}, verify = verify).json()
    scans_names = []

    if not scans['scans']:
        print('[+] Folder "' + folder + '" is empty')
    else:
        for scan in scans['scans']:
            scans_names.append(scan['name'])

        print('[+] Listing ' + str(len(scans_names)) + ' scans from folder "' + folder + '"...')

        for scan in sorted(scans_names):
            print('[+]   ' + colored(scan, 'white', attrs = ['bold']))

def get_folder_id(folder_name, url, token, verify):
    folders = requests.get(url + '/folders', headers = {'X-Cookie': 'token=' + token}, verify = verify).json()

    for folder in folders['folders']:
        if folder['name'] == folder_name:
            return folder['id']

    print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' Folder "' + folder_name + '" not found.')
    sys.exit(1)

def get_scan_id(scan_name, url, token, verify):
    scans = requests.get(url + '/scans', params = {'folder_id': folder_id}, headers = {'X-Cookie': 'token=' + token}, verify = verify).json()

    for scan in scans['folders']:
        if scan['name'] == scan_name:
            return scan['id']

    print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' Scan "' + scan_name + '" not found.')
    sys.exit(1)

def get_scan_status(scan_name, url, token, verify):
    scan_id = get_scan_id(scan_name, url, token, verify)

    return requests.get(url + '/scans/' + str(scan_id), headers={'X-Cookie': 'token=' + token}, verify = verify).json()['info']['status']

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', help = 'The host (IP or hostname) where Nessus is running on', required = True)
    parser.add_argument('--port', help = 'The port Nessus is listening on (default: 8834)', required = False, default = '8834')
    parser.add_argument('--username', help = 'Username', required = True)
    parser.add_argument('--password', help = 'Password', required = True)
    parser.add_argument('--verify-https', action="store_true", help = 'Verify SSL certificate (default: false)', required = False, default = False)
    parser.add_argument('-l', '--list-folders', action="store_true", help = 'List all the folders', required = False)
    parser.add_argument('-s', '--get-scans', help = 'List the scans contained in folder FOLDER', dest = 'folder', required = False)
    parser.add_argument('--status', help = 'Show status for scan SCAN', dest = 'scan', required = False)
    args = parser.parse_args()

    host = args.host
    port = args.port
    username = args.username
    password = args.password
    verify = args.verify_https
    folder = args.folder
    scan = args.scan

    logo()

    url = 'https://' + host + ':' + port
    print('[+] Nessus server URL:  ' + colored(url, 'white', attrs = ['bold']))

    try:
        status = requests.get(url + '/server/status', verify = verify, timeout = (5, 5)).json()
        if status['code'] == 200 and status['status'] == 'ready':
            status = colored('OK (' + status['status'] + ')', 'green')
        else:
            status = colored('NOT OK', 'red')
        print('[+] Server status:      ' + status)
    except requests.exceptions.RequestException as e:
        print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' Failed connecting to Nessus server: ' + colored(e, 'red'))
        sys.exit(1)

    token = get_token(url, username, password, verify)
    print('[+] Successfully logged in as user: ' + colored(username, 'white', attrs = ['bold']))

    session = requests.get(url + '/session', headers = {'X-Cookie': 'token=' + token}, verify = verify).json()

    if 'username' not in session or session['username'] != username:
        print(colored('ERROR!', 'red', attrs = ['reverse', 'bold']) + ' Error validating session. Exiting...')
        sys.exit(1)

    if args.list_folders:
        list_folders(url, token, verify)

    if folder:
        list_scans(folder, url, token, verify)

    if scan:
        get_scan_status(scan, url, token, verify)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main(sys.argv[1:])

#### TODO:
#### - a LOT! :-) WORK IN PROGRESS!!!!

