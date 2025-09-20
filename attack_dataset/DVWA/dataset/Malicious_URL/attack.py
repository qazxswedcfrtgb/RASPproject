import csv
import requests
from urllib.parse import urlparse, urlunparse, parse_qs
from bs4 import BeautifulSoup

DVWA_BASE = 'http://localhost:8080'
LOGIN_URL = f'{DVWA_BASE}/login.php'
ATTACK_TYPE = 'sqli'  # or 'exec', 'xss_r', ...
ATTACK_URL = f'{DVWA_BASE}/vulnerabilities/{ATTACK_TYPE}/'
DATASET = 'defacement_urls.csv'  # CSV 檔裡每行一個 url

def get_csrf_token(session):
    """ 從 login.php 擷取 CSRF Token（如果有）"""
    resp = session.get(LOGIN_URL)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find('input', {'name': 'user_token'})
    return token['value'] if token else None

def login(session):
    """登入 DVWA 並將安全等級設為 low"""
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
        # 設定安全等級為 low
        security_url = f"{DVWA_BASE}/security.php"
        token = get_csrf_token(session)
        security_data = {'security': 'low', 'seclev_submit': 'Submit'}
        if token:
            security_data['user_token'] = token
        session.post(security_url, data=security_data)
    else:
        print("❌ 登入失敗")
        exit(1)

def rewrite_url(original_url):
    parsed = urlparse(original_url)
    new_netloc = urlparse(ATTACK_URL).netloc
    new_path = urlparse(ATTACK_URL).path
    new_url = urlunparse((
        parsed.scheme,
        new_netloc,
        new_path,
        '',
        parsed.query,
        ''
    ))
    return new_url

def judge_sqli(response, id=None):
    if "First name" in response.text:
        print(f"[{id}] ✅ SQLi 成功查詢")
    elif "You have an error in your SQL syntax" in response.text:
        print(f"[{id}] ⚠️ SQL 語法錯誤")
    elif "You must be logged in" in response.text:
        print(f"[{id}] 🚫 未登入")
    elif response.status_code == 405:
        print(f"[{id}] 🚫 方法不允許")

def judge_cmdi(response, id=None):
    soup = BeautifulSoup(response.text, 'html.parser')
    pre_block = soup.find('pre')
    if not pre_block:
        # print(f"[{id}] ⚠️ 無 <pre>，無法判斷 CMDi")
        return

    lines = pre_block.text.strip().splitlines()
    extra_lines = []
    in_ping_block = False
    for line in lines:
        if line.startswith("PING "):
            in_ping_block = True
        elif in_ping_block and line.startswith("---"):
            break
        elif not in_ping_block:
            extra_lines.append(line)
        elif in_ping_block and not (
            "icmp_seq" in line or "bytes from" in line or "round-trip" in line or "%" in line
        ):
            extra_lines.append(line)

    if extra_lines:
        print(f"[{id}] ✅ CMDi 成功注入（額外輸出）")
        print("=== 額外輸出內容 ===")
        for line in extra_lines:
            print(line)
        print("="*30)
    else:
        print(f"[{id}] ❌ 無額外輸出")

def test_attack(session, url, id=None):
    new_url = rewrite_url(url)
    # print(f"[{id}] Method: GET")
    # print(f"[{id}] URL: {new_url}")
    # print("="*30)

    try:
        response = session.get(new_url)
    except requests.RequestException as e:
        print(f"[{id}] 請求失敗：{e}")
        return

    # print(f"[{id}] Response code: {response.status_code}")
    # print(response.text)
    if ATTACK_TYPE == 'sqli':
        judge_sqli(response, id)
    elif ATTACK_TYPE == 'exec':
        judge_cmdi(response, id)
    else:
        print(f"[{id}] ⚠️ 尚未實作的判斷模組：{ATTACK_TYPE}")

def main():
    session = requests.Session()
    login(session)
    with open(DATASET, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            test_attack(session, row['url'], i)

if __name__ == '__main__':
    main()
