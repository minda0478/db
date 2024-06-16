from openai import OpenAI

import matplotlib.pyplot as plt
import pandas as pd

import cve
import cwe
import exploit
import utils

import os
import re
import time
import json
import requests
import subprocess
from tqdm import tqdm
from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

chrome_options = Options()
chrome_options.add_experimental_option("detach", True)

def count_publish(cve_lists):
    cnt = 0
    del_list = []
    for c in cve_lists:
        if cve_lists[c].is_published():
            cnt += 1
        else:
            del_list.append(cve_lists[c].get_id())
    
    for id in del_list:
        del cve_lists[id]
    return cnt




def check_cwe_exploit(c, white_list=False):
    ex = exploit.exploit(c.get_id())
    cw = c.get_cwes()
    if white_list == False:
        return ex.exist_exploit()
    
    for w in white_list:
        if cwe.cwe.get_cwe(w) in cw:
            return ex.exist_exploit()
        else:
            return False

def crawling_crm(url,by,e):
    ret = ""
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(3)
        driver.get(url=url)
        ret += f"{url}\n"
        ret += driver.find_element(by,e).text
        ret += "\n"
    except:
        pass
    finally:
        driver.close()
    
    return ret

def remove_tag(text):
    t = BeautifulSoup(text,'lxml').text
    while t.find('\n\n\n') != -1:
        t = t.replace('\n\n\n', '\n')
    return t


def get_source_code(c):
    ret = ""
    #collectionURL
    #programFiles
    #repo git

    refs = c.get_ref()
    for ref in refs:
        if 'tags' in ref:
            time.sleep(0.1)
            if 'patch' in ref['tags']:
                res = requests.get(ref['url'])
                ret = f"{ref['url']}\n"
                ret += res.text
                ret += "\n"
                continue
            if 'mailing-list' in ref['tags']:
                res = requests.get(ref['url'])
                ret = f"{ref['url']}\n"
                ret += res.text
                ret += "\n"
                continue
            if 'broken-link' in ref['tags'] \
                or 'vendor-advisory' in ref['tags'] \
                or 'exploit' in ref['tags']:
                continue

        if "github" in ref['url'] \
            and ('release' not in ref['url'] or 'tag' in ref['url'])\
            and 'advisor' not in ref['url']:
            if 'tag' in ref['url']:
                res = requests.get(ref['url'])
                if res.status_code == 404:
                    continue
                soup = BeautifulSoup(res.text, 'html.parser')
                ret = ""
                for url in soup.find_all('a',attrs={'data-hovercard-type':"pull_request"}):
                    ret += crawling_crm(url+'/files',By.ID,'files_bucket')
                

                return ret
            if 'pull' in ref['url']:
                ret = crawling_crm(url+'/files',By.ID,'files_bucket')
                return ret
            if 'blob' in ref['url']:
                res = requests.get(ref['url'])
                if res.status_code != 404:
                    soup = BeautifulSoup(res.text,'html.parser')
                    code = soup.select_one('read-only-cursor-text-area').getText()
                    ret = f"{ref['url']}\n"
                    ret += code
                    ret += "\n"
                    return ret

            res = requests.get(ref['url'])
            if res.status_code != 404:
                ret = f"{ref['url']}\n"
                ret += res.text
                ret += "\n"
                continue
        elif "github" in ref['url']:
            continue

        elif "gitlab" in ref['url'] and 'cve' in ref['url'] \
            and ('release' not in ref['url'] or 'tag' in ref['url']):
            if 'blob' in ref['url']:
                ret = crawling_crm(ref['url'],By.ID,'fileHolder')
                return ret
            if 'commit' in ref['url']:
                ret = crawling_crm(ref['url'],By.CLASS_NAME,'js-diffs-batch')
                return ret
            if 'merge_requests' in ref['url']:
                ret = crawling_crm(ref['url']+'/diffs',By.ID,'diffs')
                return ret
            if 'tags' in ref['url']:
                res = requests.get(ref['url'])
                soup = BeautifulSoup(res.text, 'html.parser')
                ret = ""
                for url in soup.find_all('a',attrs={"class":"commit-sha"}):
                    ret += crawling_crm(url,By.ID,'js-diffs-batch')
                return ret
            res = requests.get(ref['url'])
            if res.status_code != 404:
                ret = f"{ref['url']}\n"
                ret += res.text
                ret += "\n"
                continue
        elif 'gitlab' in ref['url']:
            continue
        elif "git" in ref['url']:
            if 'git.kernel' in ref['url'] and 'tree':
                idx = ref['url'].find('tree')
                url = ref['url'][:idx]
                url += 'plain'
                url += ref['url'][idx+4:]
                res = requests.get(url)
                ret = f"{url}\n"
                ret += res.text
                ret += "\n"
                return ret

            elif 'git.kernel' in ref['url']:
                res = requests.get(ref['url'])
                soup = BeautifulSoup(res.text, 'html.parser')
                ret = f"{ref['url']}\n"
                ret += soup.find('table',{'summary':'diff'}).text
                ret += "\n"
                return ret
            elif 'lore.kernel' in ref['url']:
                res = requests.get(ref['url'])
                ret = f"{ref['url']}\n"
                ret += res.text
                ret += "\n"
                return ret
            elif 'commit' in ref['url']:
                ret = crawling_crm(ref['url'],By.TAG_NAME,'body')
                return ret
            elif 'tree' in ref['url']:
                ret = crawling_crm(ref['url'],By.TAG_NAME,'body')
                return ret
    return ret

def git_parse(git_url):
    os.chdir('../github_ex')

    sub = subprocess.Popen(['wsl','-e','/bin/sh','-c',
                      f'git clone {git_url} tmp'],
                      stdout=subprocess.PIPE,encoding="utf-8")
    
    sub.wait()
    data = ""
    base = './tmp'
    for fd in os.listdir(base):
        file = base+'/'+fd
        if os.path.isfile(file):
            with open(file,'r') as f:
                data += f'{file}\n'
                data += f.read()
                data += f'\n\n'

    subprocess.Popen(['wsl','-e','rm','-rf','./tmp'])

    return data

def make_exploit(c):
    cve_id = c.get_id()

    exp = exploit.exploit(cve_id,1)

    ret = ""
    for path in exp.get_path():
        path = 'c://'+path[6:]
        with open(path,"r") as f:
            p = path[path.find("exploitdb")+18:]
            ret += f"{p}\n"
            ret += f.read()
            ret += "\n"
        return ret
    for url in exp.get_github():
        ret += f"{url}\n"
        ret += git_parse(url)
        ret += "\n"
        return ret

def make_data_set(c,path='./'):
    exp = make_exploit(c)
    if exp == "":
        return 0
    
    source = get_source_code(c)
    source = remove_tag(source)
    if source == "":
        return 0
    cw = c.get_cwes()

    desc = "descriptions"

    for d in c.get_descs():
        desc += d
        desc += '\n\n'
    

    user = "source code:\n"
    user += source
    user += "\n"
    

    result = desc
    result += "exploit\n"
    result += exp

    data = {
        "messages":[
            {
                "role":"system",
                "content":"Min is a fuzzer that gives you the source code and other information that details the inputs that cause it to exploit or to crash."
            },
            {
                "role": "user",
                "content":user
            },
            {
                "role":"assistant",
                "content":result
            },
        ]
    }

    with open(path,'a',encoding='utf-8') as f:
        f.write( json.dumps(data, ensure_ascii=False) + "\n" )
    return 1




def main():
    s = 2023
    print('parse cve')
    cve_list = cve.all_dir_scan(s)

    for i in range(s,2025):
        count_publish(cve_list[str(i)])

    path = 'c:\\assignment\\wert\\test.jsonl'
    open(path, "w").close()
    print('make_data')
    m = 100000
    start = 0
    for y in cve_list:
        tbar = tqdm(cve_list[y])
        for c in tbar:
            if start > 0:
                start -= 1
                continue
            if m == 0:
                return
            tbar.set_description("analyze %s"%c)
            try:
                if check_cwe_exploit(cve_list[y][c]):
                    m += make_data_set(cve_list[y][c],path)

            except:
                continue
            

if __name__ == "__main__":
    main()