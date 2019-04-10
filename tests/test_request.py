"""Noone 压力测试。"""

import time

import socks
import requests

HEADERS = {
    'User-Agent': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko)',
    'Accept': 'text/html,application/xhtml+xml,application/xml;'
              'q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'
}


def get(url):
    start = time.time()
    with requests.Session() as session:
        session.headers.update(HEADERS)
        session.proxies = {
            'http': 'socks5://127.0.0.1:1080',
            'https': 'socks5://127.0.0.1:1080'
        }
        r = session.get(url)
        print(r.status_code)
    end = time.time()
    print('[Used %.8fs]' % (end - start))


def main():
    url = 'http://www.ruanyifeng.com/blog/'
    url = 'https://gamersky.com/'

    # while True:
        # get(url)
    get(url)


if __name__ == '__main__':
    main()
