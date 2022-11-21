# 输出日志
import datetime


def log(*msg):
    print(datetime.datetime.now(), *msg)


# 输出红色的日志 便于区分
def error(*msg):
    s = '{} '.format(datetime.datetime.now())
    for i in msg:
        s += str(i) + ' '
    print("\033[31m{}\033[0m".format(s[:-1]))
