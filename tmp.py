# 测试正则
# import re
# str = "b'Firmware=V1.0.2.68_60.0.93NA\r\nRegionTag=WNR1000v3_NA\r\nRegion=us\r\nModel=WNR1000v3\r\nInternetConnectionStatus=Up\r\nParentalControlSupported=1\r\nSOAPVersion=2.0\r\nReadyShareSupportedLevel=0\r\nSmartNetworkSupported=0\r\n'"
# m = re.search(r'(?<=Firmware=).+\s', str)
# print(m.group())
# m1 = re.search(r'(?<=RegionTag=).+\s', str)
# print(m1.group())

# # 输入输出条数不符合
# fp = open("output.txt", "r")
# lines = fp.readlines()
# fp.close()
#
# dest_list =[]
# for line in lines:
#     dest_list.append(line.split()[0])
# print(dest_list)
#
# src_list =[]
# for i in range(10):
#     src_list.append(str(i+1))
# print(src_list)
#
# for i in src_list:
#     if i not in dest_list:
#         print(i)

# test request
# import requests
#
# try:
#     response = requests.get("https://47.18.141.90:8443" + '/currentsetting.htm', timeout=3, verify=False)
# except Exception as e:
#     print(e)
# else:
#     print(response.status_code)


# 清空文件内容
def read_account(filename):
    with open(filename, 'r+', encoding='utf-8') as f:
        res = f.readlines()
        # print(res)
        f.seek(0)
        f.truncate()
    return


read_account("success_output.txt")

read_account("failure_ConnectionResetError.txt")
read_account("failure_ConnectTimeoutError.txt")
read_account("failure_failedtodecode.txt")
read_account("failure_NewConnectionError.txt")
read_account("failure_OSError.txt")
read_account("failure_Readtimedout.txt")
read_account("failure_RemoteDisconnected.txt")
read_account("failure_SSLError.txt")

read_account("failure_otherError.txt")

# 其他测试
# str = '["21 '.replace('[','').replace('"','')
# print("%s"%str)

# # # SSLError
# import requests
# import ssl
# from requests.adapters import HTTPAdapter
# from urllib3.poolmanager import PoolManager
#
# class Ssl3HttpAdapter(HTTPAdapter):
#     """"Transport adapter" that allows us to use SSLv3."""
#
#     def init_poolmanager(self, connections, maxsize, block=False):
#         # self.poolmanager = PoolManager(
#         #     num_pools=connections, maxsize=maxsize,
#         #     block=block, ssl_version=ssl.PROTOCOL_SSLv3)
#         self.poolmanager = PoolManager(
#             num_pools=connections, maxsize=maxsize,
#             block=block, ssl_version=ssl.PROTOCOL_SSLv23)
#         # PROTOCOL_SSLv23:HTTPSConnectionPool(host='64.250.10.123', port=8443): Max retries exceeded with url: /currentsetting.htm (Caused by SSLError(SSLError(1, '[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol (_ssl.c:1056)')))
#         # PROTOCOL_SSLv2:module 'ssl' has no attribute 'PROTOCOL_SSLv2'
#         # PROTOCOL_SSLv3:module 'ssl' has no attribute 'PROTOCOL_SSLv3'
#         # PROTOCOL_TLSv1:HTTPSConnectionPool(host='64.250.10.123', port=8443): Max retries exceeded with url: /currentsetting.htm (Caused by SSLError(SSLError(1, '[SSL: WRONG_SSL_VERSION] wrong ssl version (_ssl.c:1056)')))
#         # PROTOCOL_TLSv1_1:HTTPSConnectionPool(host='64.250.10.123', port=8443): Max retries exceeded with url: /currentsetting.htm (Caused by SSLError(SSLError(1, '[SSL: WRONG_SSL_VERSION] wrong ssl version (_ssl.c:1056)')))
#         # PROTOCOL_TLSv1_2:HTTPSConnectionPool(host='64.250.10.123', port=8443): Max retries exceeded with url: /currentsetting.htm (Caused by SSLError(SSLError(1, '[SSL: WRONG_SSL_VERSION] wrong ssl version (_ssl.c:1056)')))
#         # PROTOCOL_TLS: HTTPSConnectionPool(host='64.250.10.123', port=8443): Max retries exceeded with url: /currentsetting.htm (Caused by SSLError(SSLError(1, '[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol (_ssl.c:1056)')))
#         # PROTOCOL_TLS_CLIENT:Cannot set verify_mode to CERT_NONE when check_hostname is enabled.
#         # PROTOCOL_TLS_SERVER:HTTPSConnectionPool(host='64.250.10.123', port=8443): Max retries exceeded with url: /currentsetting.htm (Caused by SSLError(SSLError(1, '[SSL] called a function you should not call (_ssl.c:1056)')))
#
# def send_request_SSLError(url, index,timeout):
#     s = requests.Session()
#
#     s.mount(url, Ssl3HttpAdapter())
#     try:
#         if url.find("https") != -1:
#             response = s.get(url + '/currentsetting.htm', timeout=timeout, verify=False)
#         else:
#             response = s.get(url + '/currentsetting.htm', timeout=timeout)
#     except Exception as e:
#         print(str(e))
#         # reason = re.search(r'(?<=Caused by )\w*', str(e)).group()
#         # return save_failure_reason(url, reason, index)
#         # return save_failure_reason(url, str(e), index)
#     else:
#         # return save_success_info(url, str(response.content),index)
#         print(response.content)
#
#
#
# fp = open("failure_SSLError2.txt", "r")
# lines = fp.readlines()
# fp.close()
# # clear_file_content("failure_SSLError.txt")
#
# from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED, FIRST_COMPLETED
#
# executor = ThreadPoolExecutor(max_workers=20)
# url_dict = {}
# for line in lines:
#     index = line.split()[0]
#     url = line.split()[1]
#     url_dict[index] = url
# task_list = []
# for item in url_dict.items():
#     pass
#     # print(item[0],item[1])
#     task = executor.submit(send_request_SSLError, item[1], item[0], 3)
#     task_list.append(task)



# # 当前时间
# import time
# print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) )
