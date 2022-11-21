import json
import os

from mitmproxy import ctx
from utils import *

flag = False
isBind = False


def request(flow):
    global flag
    global isBind
    url = flow.request.url
    if url == 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=User' and isBind:
        log('保存headers')
        with open('headers.txt', 'w', encoding='utf-8') as f:
            for k, v in dict(flow.request.headers).items():
                f.write('{}: {}'.format(k, v))
                f.write('\n')
        flag = True


def response(flow):
    global flag
    global isBind
    if 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=auth&code=' in flow.request.url:
        res = json.loads(str(flow.response.text))
        if res['status'] != 200:
            error('未绑定身份信息，请先绑定')
        else:
            isBind = True
    if flag:
        os.system('close_proxy.bat')
        ctx.master.shutdown()
