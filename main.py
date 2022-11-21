import base64
import codecs
import hashlib
import json
import os
import random
import re
import sys
import threading
import time
import traceback
from binascii import b2a_hex, a2b_hex

import frida
import requests
import urllib3
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding

from utils import *

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# 定时器
class Timer:
    def __init__(self, startTime):
        self.buy_time = datetime.datetime.strptime(startTime, "%Y-%m-%d %H:%M:%S.%f")
        self.buy_time_ms = int(time.mktime(self.buy_time.timetuple()) * 1000.0 + self.buy_time.microsecond / 1000)

    # 本地时间
    def local_time(self):
        return int(round(time.time() * 1000))

    # 等待定时任务
    def start(self, advance=20):
        if advance:
            log('正在等待到达设定时间:{}，提前{}秒'.format(self.buy_time, advance))
        else:
            log('正在等待到达设定时间:{}'.format(self.buy_time))
        while True:
            if self.local_time() + advance >= self.buy_time_ms:
                log('时间到达，开始执行……')
                break


class ZmyySeckill:
    def __init__(self, config, proxy=None, headers_file='headers.txt'):
        self.config = config
        self.t = Timer(self.config['zhimiao']['startTime'])
        self.session = requests.session()
        # 默认代理
        self.proxy = proxy
        # 间隔时间
        self.interval = 0.5

        # 读取headers
        self.headers = {}
        f = open(headers_file, 'r', encoding='utf-8')
        for i in f.readlines():
            if i.rstrip():
                k, v = i.rstrip().split(': ', 2)
                if k == 'Content-Length':
                    continue
                self.headers[k.lower()] = v
        log(self.headers)

        # 读取key，ip，过期时间等
        self.get_aes_key(self.headers['cookie'])
        try:
            f = open('signature.txt', 'r', encoding='utf-8')
            self.key = str(f.read()).strip()
        except:
            error('未获取到signature，尝试重启微信，并重启脚本')
            exit()
        log('key', self.key)
        # 获取用户信息
        self.user = self.get_user()
        assert self.user
        log(self.user)

        # 获取医院信息，cid就是医院id
        self.cid = self.get_cid()
        assert self.cid
        log('医院名称', self.config['zhimiao']['cname'])
        log('医院id', self.cid)

    # base64解密
    def base64_decrypt(self, ciphertext, charset='utf-8'):
        missing_padding = len(ciphertext) % 4
        if missing_padding:
            ciphertext += ('=' * (4 - missing_padding))
        result = base64.urlsafe_b64decode(ciphertext.encode(charset))
        # result = base64.b64decode(str(ciphertext))
        # log(result)
        return result

    # aes_cbc_128 加密
    def aes_encrypt(self, text, key, iv=b'1234567890000000', charset='utf-8'):
        def pkcs7_padding(data, block_size=128):
            if not isinstance(data, bytes):
                data = data.encode(charset)
            padder = padding.PKCS7(block_size).padder()
            return padder.update(data) + padder.finalize()

        cipher = AES.new(str(key).encode(charset), AES.MODE_CBC, iv)
        return b2a_hex(cipher.encrypt(pkcs7_padding(text))).decode()

    # aes_cbc_128 解密
    def aes_decrypt(self, ciphertext, key, iv=b'1234567890000000', charset='utf-8'):
        try:
            json.loads(ciphertext)
            return ciphertext
        except Exception as e:
            pass

        def unpad(text):
            pad = ord(text[-1])
            return text[:-pad]

        cipher = AES.new(str(key).encode(charset), AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(a2b_hex(ciphertext)).decode(charset))

    # 根据cookie获取aes_key
    def get_aes_key(self, cookie, charset='utf-8'):
        assert (cookie.startswith('ASP.NET_SessionId='))
        cookie = cookie[len('ASP.NET_SessionId='):]
        # 解析出jet payload
        result = self.base64_decrypt(cookie.split('.')[1])
        # log(result)
        self.exp = eval(result)['exp']
        exp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(eval(result)['exp']))
        log('exp', exp)
        jwt = eval(str(result, charset))
        # jwt中有客户端ip 可能有限制
        # 解析出key和ip
        result = self.base64_decrypt(jwt['val'])
        pattern = b'((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)'
        ip = re.search(pattern, result).group(0)
        log('ip', str(ip, charset))

    # md5加密
    def md5(self, t):
        m = hashlib.md5()
        m.update(t.encode('utf-8'))
        return m.hexdigest()

    # 发起get请求
    def get(self, url, proxies=None, wrong_time=0, data=None):
        time.sleep(self.interval)
        if time.time() >= self.exp:
            raise Exception('cookie 过期了')
        if wrong_time >= 10:
            raise Exception('get请求出错次数过多')
        try:
            log(url)
            self.headers['zftsl'] = self.md5('zfsw_' + str(int(time.time() * 100)))
            res = self.session.get(
                url=url,
                headers=self.headers,
                params=data,
                timeout=1,
                proxies=proxies,
                verify=False
            )
            if proxies:
                log('proxies', proxies)
            if data:
                log('data', data)
            log('res.text', res.text)
            return res
        except Exception as e:
            traceback.print_exc()
            if '出错次数过多' in str(e):
                raise e
            return self.get(url, proxies, wrong_time + 1, data=data)

    # 发起post请求
    def post(self, url, data, proxies, wrong_time=0):
        if time.time() >= self.exp:
            raise Exception('cookie 过期了')
        if wrong_time >= 10:
            raise Exception('post请求出错次数过多')
        try:
            log(url)
            if proxies:
                log('proxies', proxies)
            log(data)
            log(json.dumps(data, separators=(',', ':'), ensure_ascii=False))
            params = self.aes_encrypt(json.dumps(data, separators=(',', ':'), ensure_ascii=False), self.key)
            log(params)
            self.headers['zftsl'] = self.md5('zfsw_' + str(int(time.time() * 100)))
            res = self.session.post(
                url=url,
                headers=self.headers,
                data=params,
                timeout=1,
                proxies=proxies,
                verify=False
            )
            return res
        except Exception as e:
            error('post', e)
            if '出错次数过多' in str(e):
                raise e
            return self.post(url, data, proxies, wrong_time + 1)

    def run(self, max_times=30):
        # 等待时间到达
        self.t.start(0)
        log('1. 获取pid')
        w = 0
        while True:
            if w >= max_times:
                print('获取pid出错次数太多')
                exit()
            try:
                self.pid = self.get_pid()
                break
            except:
                traceback.print_exc()
                w += 1
        log('疫苗名称', self.config['zhimiao']['vaccines'])
        log('疫苗pid', self.pid)
        n = 0
        while True:
            log('第%d论秒杀' % (n + 1))
            st = time.time()
            try:
                self.seckill()
            except Exception as e:
                traceback.print_exc()
                if '过期了' in str(e):
                    exit()
            n += 1
            log('用时:', time.time() - st)
            if n >= max_times:
                error('抢购超时')
                break

    # 秒杀
    def seckill(self, max_times=30):
        # 获取预约日期
        dates = self.get_subscribe_dates()
        rdate = random.choice(dates)
        log('预约日期', rdate)
        try:
            # 获取预约时间
            times = self.get_subscribe_times(rdate)
            for i in range(len(times)):
                try:
                    rtime = times[i]
                    log('预约时间', '{}~{}'.format(rtime['StartTime'], rtime['EndTime']))
                    mxid = rtime['mxid']

                    # 识别验证码
                    self.get_captcha(mxid)

                    # 提交预约信息
                    data = {
                        'birthday': self.user['birthday'],
                        'tel': self.user['tel'],
                        'cname': self.user['cname'],
                        'sex': self.user['sex'],
                        'idcard': self.user['idcard'],
                        'doctype': self.user['doctype'],
                        'mxid': rtime['mxid'],
                        'date': rdate,
                        'pid': self.pid,
                        'Ftime': self.config['zhimiao']['Ftime'],  # 这个代表第几针
                        'guid': '',
                    }
                    res = self.order_post(data)
                    log(res.text)
                    if res.json()['status'] == 200:
                        while True:
                            log('6. 查询订单状态')
                            ww = 0
                            try:
                                # 查询订单状态
                                res = self.get_order_status()
                                log(res.text)
                                if res.json()['status'] == 200:
                                    log('抢购成功！！！')
                                    exit()
                            except:
                                traceback.print_exc()
                                if ww >= max_times:
                                    error('应该被吞了 垃圾知苗')
                                    exit()
                                ww += 1
                    else:
                        raise Exception(res.text)
                except Exception as e:
                    error(times[i], e)
                    if i == len(times) - 1:
                        raise e
        except Exception as e:
            self.config['zhimiao']['dates'].remove(rdate)
            raise e

    # 获取用户信息
    def get_user(self):
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=User'
        return self.get(url).json()['user']

    # 获取医院id
    def get_cid(self):
        hospitals = []
        # 27是九价，28是四价
        for product in [27, 28]:
            url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=CustomerList&city=["{}","{}","{}"]&lat=&lng=&id=0&cityCode={}&product={}'.format(
                self.config['zhimiao']['province'],
                self.config['zhimiao']['city'],
                self.config['zhimiao']['county'],
                self.config['zhimiao']['cityCode'],
                product
            )
            res = self.get(url)
            hospitals.extend(res.json()['list'])
        for i in hospitals:
            if self.config['zhimiao']['cname'] in i['cname']:
                return i['id']
        raise Exception('未获取到医院信息')

    # 获取疫苗id
    def get_pid(self):
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=CustomerProduct&id={}&lat=&lng='.format(
            self.cid
        )
        res = self.get(url)
        for j in res.json()['list']:
            if self.config['zhimiao']['vaccines'] in j['text']:
                return j['id']
        raise Exception('未获取到疫苗信息')

    # 获取预约日期
    def get_subscribe_dates(self):
        log('2. 获取预约日期')
        if 'dates' not in self.config['zhimiao'] or not self.config['zhimiao']['dates']:
            url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=GetCustSubscribeDateAll&pid={}&id={}&month={}'.format(
                self.pid, self.cid, datetime.datetime.now().strftime('%Y%m')
            )
            for i in range(10):
                res = self.get(url, self.proxy)
                if 'list' not in res.json() or not res.json()['list']:
                    time.sleep(self.interval)
                    continue
                dates = [i['date'] for i in res.json()['list'] if i['enable']]
                # dates = [i['date'] for i in res.json()['list']]
                self.config['zhimiao']['dates'] = dates
                return dates
            raise Exception('当前没有可预约的日期')
        else:
            return self.config['zhimiao']['dates']

    # 获取预约时间
    def get_subscribe_times(self, day):
        log('3. 获取预约时间')
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=GetCustSubscribeDateDetail&pid={}&id={}&scdate={}'.format(
            self.pid, self.cid, day
        )
        for i in range(10):
            res = self.get(url, self.proxy)
            # res = self.get(url)
            if res.text.startswith('{') or res.text.startswith("<"):
                time.sleep(self.interval)
                continue
            ciphertext = res.text
            log('ciphertext', ciphertext)
            plaintext = self.aes_decrypt(ciphertext, self.key)
            log('plaintext', plaintext)
            times = [i for i in json.loads(plaintext)['list'] if i['qty']]
            if not times:
                # dates.remove(rdate)
                raise Exception('当前日期{}没有可预约的时间'.format(day))
            return times
        raise Exception('当前日期{}没有可预约的时间'.format(day))

    # 识别验证码
    def get_captcha(self, mxid):
        log('4. 验证码')
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=GetCaptcha&mxid={}'.format(mxid)
        res = self.get(url, self.proxy)
        # res = self.get(url)
        if res.json()['status'] == 200:
            # 更新cookie
            # log(self.headers['cookie'])
            cd = requests.utils.dict_from_cookiejar(res.cookies)
            self.headers['cookie'] = '{}={}'.format('ASP.NET_SessionId', cd['ASP.NET_SessionId'])
        else:
            with open('{}.txt'.format(int(time.time() * 1000)), 'w', encoding='utf-8') as f:
                f.write(res.text)
            raise Exception(res.text)

    # 提交订单
    def order_post(self, data):
        log('5. 提交订单')
        url = 'https://cloud.cn2030.com/sc/api/User/OrderPost'
        res = self.post(url, data, self.proxy)
        if res.json()['status'] != 200:
            if res.json()['msg'] == '身份证不在预约范围.':
                error('order_post', res.text)
                exit()
            print(res.text)
            raise Exception(res.text)
        # 更新cookie
        # log(self.headers['cookie'])
        cd = requests.utils.dict_from_cookiejar(res.cookies)
        self.headers['cookie'] = '{}={}'.format('ASP.NET_SessionId', cd['ASP.NET_SessionId'])
        return res

    # 查询订单状态
    def get_order_status(self):
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=GetOrderStatus'
        res = self.get(url)
        if res.json()['status'] != 200:
            raise Exception(res.text)
        return res


def hook(target_process='wechat.exe'):
    try:
        session = frida.attach(target_process)
    except:
        traceback.print_exc()
        exit()
    with codecs.open('signature.js', 'r', 'utf-8') as f:
        source = f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()


def on_message(message, data):
    if 'payload' in message:
        d = json.loads(message['payload']['signature'])
        rawData = d['rawData']
        signature = d['signature'][:16]
        print('signature', signature)
        f = open('signature.txt', 'w', encoding='utf-8')
        f.write(signature)
        f.flush()
    else:
        print(message)


def open_proxy(port):
    os.system('chcp 65001')
    os.system('open_proxy.bat {}'.format(port))


def close_proxy():
    log('关闭代理')
    os.system('chcp 65001')
    os.system('close_proxy.bat')
    log('关闭代理成功！')


def capture(port='8888'):
    # 开启代理配置
    open_proxy(port)
    # 开启监听
    os.system('mitmdump -q -s {} -p  {}'.format('capture.py', port))


if __name__ == '__main__':
    config = {
        # 知苗配置
        "zhimiao": {
            # 省
            "province": "重庆市",
            # 市
            "city": "重庆市",
            # 县/区 可留空
            "county": "",
            # 城市代码
            "cityCode": "500000",
            # 疫苗名称
            "vaccines": "九价人乳头瘤病毒疫苗",
            # 医院名称
            "cname": "重庆市荣昌区昌州街道社区卫生服务中心",
            # 抢购开始时间
            "startTime": "2022-06-24 09:15:00.000",
            # 接种日期，如果公告有接种日期可以提前配置，没有时会自动获取
            # "dates": ["2022-06-15"],
            # 第几针
            "Ftime": 1
        }
    }
    # 设置当前工作目录
    os.chdir(os.path.dirname(__file__))
    if os.path.exists('signature.txt'):
        os.remove('signature.txt')
    # 启动hook线程
    t = threading.Thread(target=hook)
    t.start()
    # 启动抓包线程
    t1 = threading.Thread(target=capture)
    t1.start()
    t1.join()
    z = ZmyySeckill(config)
    z.run()
