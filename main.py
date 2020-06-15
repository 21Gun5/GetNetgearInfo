import requests
import re
import warnings
import ssl
import datetime
import threading
import time
import fcntl
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED, FIRST_COMPLETED
from urllib3.poolmanager import PoolManager
from requests.adapters import HTTPAdapter
# from concurrent.futures import ThreadPoolExecutor

# 全局变量

mutex = threading.Lock()
thread_number = 300  # 控制线程数
total_item = 0
success_item = 0
empty_item = 0
failure_ConnectionResetError = 0
failure_ConnectTimeoutError = 0
failure_NewConnectionError = 0
failure_OSError = 0
failure_ReadTimeoutError = 0
failure_RemoteDisconnected = 0
failure_SSLError = 0
failure_FailedToDecode = 0
failure_OtherError = 0

# 不显示因verigy=false的产生的警告
warnings.filterwarnings('ignore')

# 解决RemoteDisconnected/SSLError所需
CIPHERS = ('ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
    'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
    '!eNULL:!MD5')
class DESAdapter(HTTPAdapter):
    """
    A TransportAdapter that re-enables 3DES support in Requests.
    """
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)
class Ssl3HttpAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to use SSLv3."""

    def init_poolmanager(self, connections, maxsize, block=False):
        # self.poolmanager = PoolManager(
        #     num_pools=connections, maxsize=maxsize,
        #     block=block, ssl_version=ssl.PROTOCOL_SSLv3)
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_version=ssl.PROTOCOL_TLS)
        # PROTOCOL_SSLv23
        # PROTOCOL_SSLv2
        # PROTOCOL_SSLv3
        # PROTOCOL_TLSv1
        # PROTOCOL_TLSv1_1
        # PROTOCOL_TLSv1_2
        # PROTOCOL_TLS
        # PROTOCOL_TLS_CLIENT
        # PROTOCOL_TLS_SERVER

# 发起请求、多线程的target
def send_request(url, index,timeout):
    global empty_item
    try:
        if url.find("https") != -1:
            response = requests.get(url + '/currentsetting.htm', timeout=timeout, verify=False)
        else:
            response = requests.get(url + '/currentsetting.htm', timeout=timeout)
    except Exception as e:
        # reason = re.search(r'(?<=Caused by )\w*', str(e)).group()
        # return save_failure_reason(url, reason, index)
        return save_failure_reason(url, str(e), index)
    else:
        try:
            Firmware = re.search(r'(?<=Firmware=)[._0-9a-zA-Z]*', str(response.content)).group()
            RegionTag = re.search(r'(?<=RegionTag=)[._0-9a-zA-Z]*', str(response.content)).group()
        except Exception as e:
            Firmware = None
            RegionTag = None
            empty_item +=1
        return save_success_info(index,url,Firmware,RegionTag)
def send_request_OSError(url, index,timeout):
    global empty_item
    header = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15}"
    }
    try:
        if url.find("https") != -1:
            response = requests.get(url + '/currentsetting.htm', headers=header,timeout=timeout, verify=False)
        else:
            response = requests.get(url + '/currentsetting.htm', headers=header,timeout=timeout)
    except Exception as e:
        # reason = re.search(r'(?<=Caused by )\w*', str(e)).group()
        # return save_failure_reason(url, reason, index)
        return save_failure_reason(url, str(e), index)
    else:
        try:
            Firmware = re.search(r'(?<=Firmware=)[._0-9a-zA-Z]*', str(response.content)).group()
            RegionTag = re.search(r'(?<=RegionTag=)[._0-9a-zA-Z]*', str(response.content)).group()
        except Exception as e:
            Firmware = None
            RegionTag = None
            empty_item +=1
        return save_success_info(index,url,Firmware,RegionTag)
def send_request_RemoteDisconnected(url, index,timeout):

    global empty_item

    s = requests.Session()
    s.mount('https://some-3des-only-host.com', DESAdapter())

    try:
        if url.find("https") != -1:
            response = s.get(url + '/currentsetting.htm', timeout=timeout, verify=False)
        else:
            response = s.get(url + '/currentsetting.htm', timeout=timeout)
    except Exception as e:
        # reason = re.search(r'(?<=Caused by )\w*', str(e)).group()
        # return save_failure_reason(url, reason, index)
        return save_failure_reason(url, str(e), index)
    else:
        try:
            Firmware = re.search(r'(?<=Firmware=)[._0-9a-zA-Z]*', str(response.content)).group()
            RegionTag = re.search(r'(?<=RegionTag=)[._0-9a-zA-Z]*', str(response.content)).group()
        except Exception as e:
            Firmware = None
            RegionTag = None
            empty_item +=1
        return save_success_info(index,url,Firmware,RegionTag)
def send_request_SSLError(url, index,timeout):
    global empty_item

    s = requests.Session()
    s.mount(url, Ssl3HttpAdapter())

    try:
        if url.find("https") != -1:
            response = s.get(url + '/currentsetting.htm', timeout=timeout, verify=False)
        else:
            response = s.get(url + '/currentsetting.htm', timeout=timeout)
    except Exception as e:
        # reason = re.search(r'(?<=Caused by )\w*', str(e)).group()
        # return save_failure_reason(url, reason, index)
        return save_failure_reason(url, str(e), index)
    else:
        try:
            Firmware = re.search(r'(?<=Firmware=)[._0-9a-zA-Z]*', str(response.content)).group()
            RegionTag = re.search(r'(?<=RegionTag=)[._0-9a-zA-Z]*', str(response.content)).group()
        except Exception as e:
            Firmware = None
            RegionTag = None
            empty_item += 1
        return save_success_info(index, url, Firmware, RegionTag)

# 保存信息
def save_success_info(index,url, Firmware,RegionTag):
    global success_item
    success_item += 1



    mutex.acquire()
    with open('success_output.txt', 'a+') as f:
        # fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.write("%-5s %-30s %-20s %s\n" % (index,url, Firmware,RegionTag))
        # print("%-5s %-30s %-20s %s\n" % (index,url, Firmware,RegionTag))
        f.close()
        # fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    mutex.release()
def save_failure_reason(url, errorInfo,index):
    # mutex.acquire()
    # with open('success_output.txt', 'a+') as f:
    #     # fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    #     f.write("%-5s %-30s ---- %s \n" % (index, url, errorInfo))
    #     f.close()
    #     # fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    # mutex.release()

    # global failure_item
    # failure_item += 1

    errorFile = what_error(errorInfo)
    # mutex.acquire()
    f2 = open(errorFile, 'a+')
    f2.write("%-5s %-30s ---- %s \n" % (index, url, errorInfo))
    # print("%-5s %-30s ---- %s \n" % (index, url, errorInfo))
    f2.close()
    # mutex.release()

# 其他辅助函数
def clear_file_content(filename):
    with open(filename, 'r+', encoding='utf-8') as f:
        res = f.readlines()
        # print(res)
        f.seek(0)
        f.truncate()
    return
def what_error(errorInfo):
    global failure_ConnectionResetError,failure_ConnectTimeoutError,failure_NewConnectionError,failure_OSError,failure_ReadTimeoutError,\
        failure_RemoteDisconnected,failure_SSLError,failure_FailedToDecode,failure_OtherError

    if errorInfo.find("ConnectTimeoutError") != -1:
        error_file = "failure_ConnectTimeoutError.txt"
        failure_ConnectTimeoutError+=1
    elif errorInfo.find("Read timed out") != -1:
        error_file = "failure_Readtimedout.txt"
        failure_ReadTimeoutError+=1
    elif errorInfo.find("OSError") != -1:
        error_file = "failure_OSError.txt"
        failure_OSError+=1
    elif errorInfo.find("NewConnectionError") != -1:
        error_file = "failure_NewConnectionError.txt"
        failure_NewConnectionError+=1
    elif errorInfo.find("failed to decode") != -1:
        error_file = "failure_failedtodecode.txt"
        failure_FailedToDecode+=1
    elif errorInfo.find("RemoteDisconnected") != -1:
        error_file = "failure_RemoteDisconnected.txt"
        failure_RemoteDisconnected+=1
    elif errorInfo.find("ConnectionResetError") != -1:
        error_file = "failure_ConnectionResetError.txt"
        failure_ConnectionResetError += 1
    elif errorInfo.find("SSLError") != -1:
        error_file = "failure_SSLError.txt"
        failure_SSLError+=1
    else:
        error_file = "failure_otherError.txt"
        failure_OtherError += 1
    return error_file

# 重试Error的请求
def handle_timeout_error(timeout):
    f = open('success_output.txt', 'a+')
    f.write(
        "--------------------------------- retry Connect/ReadTimeoutError (timeout: %d)--------------------------------\n\n" % timeout)
    f.close()

    print(
        "--------------------------------- retry Connect/ReadTimeoutError (timeout: %d)--------------------------------\n\n" % timeout)

    fp = open("failure_ConnectTimeoutError.txt", "r")
    lines = fp.readlines()
    fp.close()

    fp2 = open("failure_Readtimedout.txt", "r")
    lines2 = fp2.readlines()
    fp2.close()

    clear_file_content("failure_ConnectTimeoutError.txt")
    clear_file_content("failure_Readtimedout.txt")
    global failure_ConnectTimeoutError,failure_ReadTimeoutError
    failure_ConnectTimeoutError=0
    failure_ReadTimeoutError=0

    global thread_number
    executor = ThreadPoolExecutor(max_workers=thread_number)
    url_dict = {}
    for line in lines:
        index = line.split()[0]
        url = line.split()[1]
        url_dict[index] = url
    for line in lines2:
        index = line.split()[0]
        url = line.split()[1]
        url_dict[index] = url
    task_list = []
    for item in url_dict.items():
        task = executor.submit(send_request, item[1],item[0],timeout)
        # print(item[0],item[1])
        task_list.append(task)

    wait(task_list, return_when=ALL_COMPLETED)
    return
def handle_SSL_error():
    f = open('success_output.txt', 'a+')
    f.write("--------------------------------- retry SSLError--------------------------------\n\n")
    f.close()

    print("--------------------------------- retry SSLError--------------------------------\n\n")

    fp = open("failure_SSLError.txt", "r")
    lines = fp.readlines()
    fp.close()


    clear_file_content("failure_SSLError.txt")
    global failure_SSLError
    failure_SSLError=0

    global thread_number

    executor = ThreadPoolExecutor(max_workers=thread_number)
    url_dict = {}
    for line in lines:
        index = line.split()[0]
        url = line.split()[1]
        url_dict[index] = url
    task_list = []
    for item in url_dict.items():
        pass
        # print(item[0],item[1])
        # task = executor.submit(send_request_SSLError, item[1], item[0], 3)
        # task_list.append(task)

    wait(task_list, return_when=ALL_COMPLETED)
    return
def handle_OS_error():
    f = open('success_output.txt', 'a+')
    f.write("--------------------------------- retry OSError--------------------------------\n\n")
    f.close()

    print("--------------------------------- retry OSError--------------------------------\n\n")

    fp = open("failure_OSError.txt", "r")
    lines = fp.readlines()
    fp.close()


    clear_file_content("failure_OSError.txt")
    global failure_OSError
    failure_OSError=0

    global thread_number
    executor = ThreadPoolExecutor(max_workers=thread_number)
    url_dict = {}
    for line in lines:
        index = line.split()[0]
        url = line.split()[1]
        url_dict[index] = url
    task_list = []
    for item in url_dict.items():
        # print(item[0],item[1])
        task = executor.submit(send_request_OSError, item[1], item[0], 3)
        # print(item[0],item[1])
        task_list.append(task)

    wait(task_list, return_when=ALL_COMPLETED)
    return
def handle_RemoteDisconnected_error():
    f = open('success_output.txt', 'a+')
    f.write("--------------------------------- retry RemoteDisconnected--------------------------------\n\n")
    f.close()

    print("--------------------------------- retry RemoteDisconnected--------------------------------\n\n")

    fp = open("failure_RemoteDisconnected.txt", "r")
    lines = fp.readlines()
    fp.close()


    clear_file_content("failure_RemoteDisconnected.txt")
    global failure_RemoteDisconnected
    failure_RemoteDisconnected=0

    global thread_number
    executor = ThreadPoolExecutor(max_workers=thread_number)
    url_dict = {}
    for line in lines:
        index = line.split()[0]
        url = line.split()[1]
        url_dict[index] = url
    task_list = []
    for item in url_dict.items():
        # print(item[0],item[1])

        task = executor.submit(send_request_RemoteDisconnected, item[1], item[0], 3)
        task_list.append(task)

    wait(task_list, return_when=ALL_COMPLETED)
    return
def handle_ConnectionResetError_error():
    f = open('success_output.txt', 'a+')
    f.write("--------------------------------- retry ConnectionResetError--------------------------------\n\n")
    f.close()

    print("--------------------------------- retry ConnectionResetError--------------------------------\n\n")

    fp = open("failure_ConnectionResetError.txt", "r")
    lines = fp.readlines()
    fp.close()


    clear_file_content("failure_ConnectionResetError.txt")
    global failure_ConnectionResetError
    failure_ConnectionResetError=0

    global thread_number
    executor = ThreadPoolExecutor(max_workers=thread_number)
    url_dict = {}
    for line in lines:
        index = line.split()[0]
        url = line.split()[1]
        url_dict[index] = url
    task_list = []
    for item in url_dict.items():
        pass
        # print(item[0],item[1])

        # task = executor.submit(send_request3, item[1], item[0], 3)
        # task_list.append(task)

    wait(task_list, return_when=ALL_COMPLETED)
    return

if __name__ == '__main__':
    begin = datetime.datetime.now()
    fp = open("NetGear.txt", "r")
    lines = fp.readlines()
    fp.close()

    executor = ThreadPoolExecutor(max_workers=thread_number)
    url_list = []
    for line in lines:
        total_item += 1
        (ip, port, isHttps) = line.split()
        if isHttps == 'TRUE':
            url = "https://%s:%s" % (ip, port)
        else:
            url = "http://%s:%s" % (ip, port)
        url_list.append(url)

    task_list = []
    for i in url_list:
        task = executor.submit(send_request, i, str(url_list.index(i)+1),3)
        task_list.append(task)


    # 第一波结束
    wait(task_list, return_when=ALL_COMPLETED)


    print("time: %f\n" %((datetime.datetime.now() - begin).total_seconds()))

    f = open('success_output.txt', 'a+')
    f.write("time: %f\n" % ((datetime.datetime.now() - begin).total_seconds()))
    f.write("--------------------------------- retry Error --------------------------------\n\n")
    f.close()

    # 重试各种error
    handle_OS_error()
    handle_RemoteDisconnected_error()
    # handle_ConnectionResetError_error()#here
    # handle_SSL_error()#here
    for i in [5, 8, 12]:
        handle_timeout_error(i)

    print("\ntotal time: %f\n" % ((datetime.datetime.now() - begin).total_seconds()))
    print(time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime()))
    print("current thread numbers: %d\n" % thread_number)
    print("total: %d, success: %d(empty:%d), failure: %d\n" % (
    total_item, success_item, empty_item, total_item - success_item))
    print(
        "ConnectionResetError: %d, ConnectTimeoutError: %d, NewConnectionError: %d, OSError: %d, ReadTimeoutError: %d, RemoteDisconnected: %d, SSLError: %d, FailedToDecode: %d" \
        % (failure_ConnectionResetError, failure_ConnectTimeoutError, failure_NewConnectionError, failure_OSError,
           failure_ReadTimeoutError, failure_RemoteDisconnected, failure_SSLError, failure_FailedToDecode)
        )

    f = open('success_output.txt', 'a+')
    f.write("\ntotal time: %f\n" % ((datetime.datetime.now() - begin).total_seconds()))
    f.write(time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime()))
    f.write("current thread numbers: %d\n"%thread_number)
    f.write("total: %d, success: %d(empty:%d), failure: %d\n"%(total_item,success_item,empty_item,total_item-success_item))
    f.write("ConnectionResetError: %d, ConnectTimeoutError: %d, NewConnectionError: %d, OSError: %d, ReadTimeoutError: %d, RemoteDisconnected: %d, SSLError: %d, FailedToDecode: %d"\
          %(failure_ConnectionResetError,failure_ConnectTimeoutError,failure_NewConnectionError,failure_OSError,failure_ReadTimeoutError,failure_RemoteDisconnected,failure_SSLError,failure_FailedToDecode)
          )
    f.close()







