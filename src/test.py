import os
import cwe
import cve
import requests
from bs4 import BeautifulSoup



r = requests.get("https://velog.io/@wlsdlkim/spartaweb2")

a = BeautifulSoup('testsdfsdfs'+r.text,'lxml')

print(a.text)
