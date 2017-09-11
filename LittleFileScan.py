#!/usr/bin/env python
# coding:utf-8

"""
this is generate tmp file and other back file
then make sure it's exist;

"""

import sys
from config import *
import json
import urlparse
import requests
import time
import re
import Queue
import threading
import argparse
import multiprocessing
from libs.common import *
from libs.GenerateDict import ProcessDic

class myFileScan:
    def __init__(self, url, custom_extion="php",full_scan=False, verbose=True):
        # the url only be www.iqiyi.com or 127.0.0.1:8080
        self.url = compeleUrl(url)

        # self.url_queue = Queue.Queue()
        self.file_queue = Queue.Queue()
        self.lock = threading.Lock()
        self.STOP_ME = False
        self.full_scan = full_scan
        self.verbose = verbose
        self.custom_extion = custom_extion



        #erro flag()()
        # error flag pattern compile
        # print page_not_found_reg
        self.error_pattern = re.compile(page_not_found_reg)

        self.has_404 = True
        self.error_status_code = 404
        self.error_flag = False
        self.error_content_length = 0
        self.dir_in_content = False
        self.error_location = ""




        # available dirs
        self.fuzz_webdirs = []
        self.fuzz_filename = []
        self.available_dirs = []
        self.available_file = []

        self.generateFileAndDir()

        # check 404
        self.checkUrl()
        self.check_404(types="file")
        self.checkFile()




    def generateFileAndDir(self):
        fuzz_bak = ProcessDic(package_ext_dict).parser()
        fuzz_tmp = ProcessDic(tempfile_ext_dict).parser()

        bak_ext_re = '|'.join(fuzz_bak).replace('.', '\.') # 生成常见备份文件规则
        tmp_ext_re = '|'.join(fuzz_tmp).replace('.', '\.') # 生成常见临时文件规则
        fuzz_filename_replace = {'%EXT%':self.custom_extion,'%BAK_EXT%':bak_ext_re}
        fuzz_filename = ProcessDic(filename_dict,fuzz_filename_replace).parser()

        # generate fuzz_tmp and add to fuzz_filename
        fuzz_filename_replace = {'%EXT%':self.custom_extion,'%BAK_EXT%':tmp_ext_re}
        fuzz_filename += ProcessDic(filename_dict,fuzz_filename_replace).parser()

        fuzz_filename = list(set(fuzz_filename))

        fuzz_webdirs = ProcessDic(directory_dict).parser()
        fuzz_webdirs_common = ProcessDic(directory_common_dict).parser()
        fuzz_webdirs += fuzz_webdirs_common
        fuzz_webdirs.append("/")
        fuzz_webdirs = list(set(fuzz_webdirs))


        self.fuzz_filename = fuzz_filename
        self.fuzz_webdirs = fuzz_webdirs

        # default generate 188 dirs and 868 files(bak & tmp)
        # so next, we fuzz dirs, and add possible dirs, then we generate dirs and files

    def check_404(self, types="dir"):
        error_dir = "this_is_error_dirs_test/"
        error_files = "this_is_error_files_test/hello.html"


        # Stitching url
        if types == "dir":
            _ = self.url + "/" + error_dir
        elif types == "file":
            _ = self.url + "/" + error_files
        else:
            raise Exception("[-] [Error] [check_404] types not Identify")
        try:
            resp = requests.get(_, headers=headers, timeout=5, allow_redirects=True, verify=allow_ssl_verify)
            _content = decode_response_text(resp.content)
            #_content = _content.replace("\r\n", "").replace(" ", "")

            self.error_status_code = resp.status_code

            # if 302 or 301, get Location
            if resp.url != _:
                self.error_location = resp.url
            else:
                self.error_location = ""
            if self.error_pattern.findall(_content):
                self.error_flag = True
            else:
                self.error_flag = False
            # if resp.status_code in [301, 302] and "Location" in resp.headers:
            #     self.error_location = resp.headers["Location"]
            self.error_content_length = len(_content)
        except Exception as e:
            self.has_404 = False
            print "[-] [Error] [myFileScan] [check_404] Request Error " + str(e)




    def verifyAlive(self, dirs, types="dir", compress=False):
        # 如果认为是404，返回False, 否则返回True


        try:
            # 判断是文件夹还是文件
            if types == "dir":
                _url = self.url + dirs + "/"
            else:
                _url = self.url + dirs

            # 判断是否是压缩文件, 只有在types="file"时，compress才为True
            if types=="file" and compress:
                #返回206, 且content-type不为html的即为真
                resp = requests.get(_url, headers=compress_headers, timeout=timeout, allow_redirects=False, verify=allow_ssl_verify)
                
                if resp.status_code == 206:
                    print "[+] [Info] [myFileScan] [verifyAlive] verify: {:25} status_code: {}".format(_url, resp.status_code)
                    if "Content-Type" in resp.headers:
                        if "text/html" not in resp.headers["Content-Type"]:
                            return True
                        else:
                            return False
                    else:
                        return False
                else:
                    return False

            else:
                resp = requests.get(_url, headers=headers, timeout=timeout, allow_redirects=True, verify=allow_ssl_verify)
                _content = decode_response_text(resp.content)
                # 判断是否在400, 404, 501, 502, 503, 505,如果是直接返回False
                if self.verbose:
                    print "[+] [Info] [myFileScan] [verifyAlive] verify: {:25} status_code: {}".format(_url, resp.status_code)
                if resp.status_code in [400, 403, 404, 414, 405, 500, 501, 502, 503, 505]:
                    return False

                if resp.status_code in [301, 302]:
                    if "Location" in resp.headers:
                        if resp.headers["Location"] == self.error_location:
                            return False
                
                # 直接匹配错误标识
                if self.error_flag:
                    if self.error_pattern.findall(_content):
                        return False
                    else:
                        return True

                
                # 如果有404错误页面的响应
                if self.has_404:
                    # 如果返回码不是404, 但是判断是否是与error_status_code
                    if resp.status_code == self.error_status_code:
                        mins = min(self.error_content_length, len(_content))
                        if mins == 0:
                            mins = 10.0
                        if abs(float(self.error_content_length, len(_content))) / mins > 0.3:
                            return True
                        else:
                            return False 

                    # 如果不在上边，且不和error_code相等，那么先认为为True
                    else:
                        return False
                else:
                    # 如果check_404请求失败，怎么办呢？, 先return True
                    return False

        except Exception as e:
            # 如果出错了，认为是True, 即404
            print "[-] [Error] [myFileScan] [verifyAlive] " + str(e)
            return False

        # 这样判断，首先判断是否是404,如果是，那么404标志设置为true
        #
        # 如果不是404, 判断是否有flag值匹配，如果匹配，那么has_flag = True
        #             并判断是否为302, 是302的话，标记302的 location
        # 如果无匹配，那么看错误长度 error_length, 错误长度在一定的相差范围内，则认为是不存在的


    """
    def compeleUrl(self):
        # judge if self.url contains ":"
        scheme = "http"
        if ":" in self.url:
            # judge if 443
            if self.url.split(":") == "443":
                scheme = "https"
            else:
                scheme = "http"
        # judge if start with "://"
        if self.url.startswith("://"):
            self.url = self.url[3:]
        elif self.url.startswith("//"):
            self.url = self.url[2:]

        # now judge if start with http
        if not self.url.startswith("http"):
            self.url = scheme + "://" + self.url
        # last, remove last "/"
        self.url = self.url.rstrip("/")
    """


    # 先写一块吧，回头再拆开
    def checkUrl(self):
        for webdir in self.fuzz_webdirs:
            if self.verifyAlive(webdir):
                self.available_dirs.append(webdir)
        #self.available_dirs.append("/")
        if not self.available_dirs:
            self.available_dirs.append("/")
        print self.available_dirs
        print "that's all available_dirs"
        #time.sleep(10)


    def checkFile(self):
        for webdir in self.available_dirs:
            if not webdir.endswith("/"):
                webdir += "/"
            for files in self.fuzz_filename:
                _file = webdir + files
                compress = False
                for i in ["rar","zip", "gz", "tar", "tgz", "tar.gz", "7z", "z", "bz2", "tar.bz2","iso", "cab"]:
                    if _file.find(i) != -1:
                        compress = True
                        break
                self.file_queue.put((_file, compress))

        # 添加王松的字典进去
        if self.full_scan:
            with open(extend_dict, "r") as f:
                for line in f.xreadlines():
                    if line.startswith("#"):
                        continue
                    compress = False
                    line = line.strip()
                    try:
                        if "".join(line.split(".")[1:]) in ["rar","zip", "gz", "tar", "tgz", "tar.gz", "7z", "z", "bz2", "tar.bz2","iso", "cab"]:
                            compress = True
                        self.file_queue.put((line, compress))
                    except Exception as e:
                        print "[Error!]"
                        self.file_queue((line, compress))


    def runFuzz(self):

        while (not self.file_queue.empty()) and self.STOP_ME == False:
            _ = self.file_queue.get()
            # print "[runFuzz] Url:\t" + str(_[0])
            result = self.verifyAlive(_[0], types="file", compress=_[1])
            if result:
                self.lock.acquire()
                with open("vuln.lst", "a+") as f:
                    f.write(self.url + _[0] + "\n")
                self.lock.release()


def parseArgs():
    parser =  argparse.ArgumentParser()
    parser.add_argument("--host", help="the target host")
    parser.add_argument("--ext", help="the extend name, default php", default="php")
    parser.add_argument("-v", help="show more detail when running", action="store_true")
    parser.add_argument("-f", help="file contains ip:port or subDomais each line")
    parser.add_argument("--full", help="Use All Dict (May be more False positives and take more time)", action="store_true")
    parser.add_argument("-t", "--threadnum", help="the number of thread count, default 15", default=15)
    args = parser.parse_args()
    if args.host is None and args.f is None:
        print "[--host/-f ] Must Contains One"
        parser.print_usage()
        exit(0)
    else:
        return args


def check_url_alive(url):
    url = compeleUrl(url)
    print "[check_url_alive]:\t" + url
    try:
        resp = requests.get(url, headers={"User-Agent": "check_url_alive", "Connection": "Close"}, timeout=5, allow_redirects=False, verify=False)
        return True
    except:
        return False


def compeleUrl(url):
    # judge if self.url contains ":"
    scheme = "http"
    if ":" in url:
        # judge if 443
        if url.split(":")[-1] == "443":
            scheme = "https"
        else:
            scheme = "http"
    # judge if start with "://"
    if url.startswith("://"):
        url = url[3:]
    elif url.startswith("//"):
        url = url[2:]

    # now judge if start with http
    if not url.startswith("http"):
        url = scheme + "://" + url
    # last, remove last "/"
    url = url.rstrip("/")
    return url


def ScanApi(host, args):
    print str(host) + str(args)
    custom_extion = args.ext
    verbose = args.v
    full_scan = args.full
    a = myFileScan(host, custom_extion=custom_extion, verbose=verbose, full_scan=full_scan)
    threads = []
    for i in range(int(args.threadnum)):
        thd = threading.Thread(target=a.runFuzz)
        threads.append(thd)
        thd.setDaemon(True)
        thd.start()
    
    while True:
        count = 0
        for thd in threads:
            if thd.is_alive():
                count += 1

        if count == 0:
            break
        else:
            try:
                time.sleep(1)
            except KeyboardInterrupt as e:
                print '\n[WARNING] User aborted, wait all slave threads to exit, current(%i)' % threading.activeCount()
                a.STOP_ME = True


def batchFileScan(args):
    custom_extion = args.ext
    verbose = args.v
    full_scan = args.full
    pool = multiprocessing.Pool(4)
    target_queue = Queue.Queue()
    if args.f:
        with open(args.f, "r") as f:
            x = f.readlines()

        for line in x:
            if not check_url_alive(line.strip()):
                continue
            print "[batchFileScan] add \t" + line.strip()
            target_queue.put(line.strip())
    
    while not target_queue.empty():
        host = target_queue.get(timeout=1)
        print "[test] [Host]:\t" + host
        pool.apply(ScanApi, (host, args))
    
    pool.close()
    pool.join()
    print 'All subprocesses done.'


if __name__ == '__main__':
    args = parseArgs()
    batchFileScan(args)
