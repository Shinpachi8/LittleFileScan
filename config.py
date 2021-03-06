# encoding: utf-8
# 全局配置文件

import sys
import random

# 字典来自文件列表
directory_dict = './dict/directory.lst'
directory_common_dict = './dict/directory_common.lst'
filename_dict = './dict/filename.lst'
package_ext_dict = './dict/package_ext.lst'
tempfile_ext_dict = './dict/tmpfile_ext.lst'


#王松的字典
extend_dict = "./dict/dict.txt"

#lijiejie的规则 
l_black = "./dict/black.list"
l_white = "./dict/white.list"


# 每个域名扫描时长最多为(分)
TIMEOUT = 20

# 扫描域名策略
# 1 = 和域名全称相关: 包含 job.wooyun.org
# 2 = 和主域名相关: 包含 wooyun.org
# 3 = 和域名的名字相关: 包含 wooyun
basedomain = 2

# 判断文件或目录存在的状态码，多个以逗号隔开
# exclude_status = [200,403]
exclude_status = [200]

# 预设默认扩展名
custom_extion = 'php' # 自定义扩展名
default_extion = sys.argv[2] if len(sys.argv) == 3 else custom_extion

# 判断文件是否存在正则，如果页面存在如下定义的内容，将url从结果中剔除
page_not_found_reg = r'404|[nN]ot [fF]ound|不存在|未找到|Error|410 Gone|invalid service url|Bad Request'

# 检测返回的结果集条数限制，超过多少条判定为误报
resulst_cnt_val = 30

# 是否开启https服务器的证书校验
allow_ssl_verify = False

# 数据库文件
sqlfile = ['data','install','web','user', 'members']
sqlfile_ext = ['.sql','.bak','.sql.tar.gz','.sql.zip','.sql.rar']

# 线程数
threads_count = 32

# -------------------------------------------------
# requests 配置项
# -------------------------------------------------

# 超时时间
timeout = 6

# 是否允许URL重定向
allow_redirects = True

# 是否允许继承http Request类的Session支持，在发出的所有请求之间保持cookies。
allow_http_session = True

# 是否允许随机User-Agent
allow_random_useragent = True

# 是否允许随机X-Forwarded-For
allow_random_x_forward = True

# 代理配置
proxies = {
	# "http": "http://user:pass@10.10.1.10:3128/",
	# "https": "http://10.10.1.10:1080",
	# "http": "http://127.0.0.1:8118", # TOR 洋葱路由器
}

# 随机HTTP头
USER_AGENTS = [
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
	"Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
	"Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
	"Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
	"Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
	"Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
	"Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
	"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
	"Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
]

# 随机生成User-Agent
def random_useragent(condition=False):
	if condition:
		return random.choice(USER_AGENTS)
	else:
		return USER_AGENTS[0]

# 随机X-Forwarded-For，动态IP
def random_x_forwarded_for(condition=False):
	if condition:
		return '%d.%d.%d.%d' % (random.randint(1, 254),random.randint(1, 254),random.randint(1, 254),random.randint(1, 254))
	else:
		return '8.8.8.8'

# HTTP 头设置
headers = {
	'User-Agent': random_useragent(allow_random_useragent),
	'X_FORWARDED_FOR': random_x_forwarded_for(allow_random_x_forward),
	# 'Referer' : 'http://www.google.com',
	# 'Cookie': 'whoami=wyscan_dirfuzz',
}

compress_headers = {
	'User-Agent': random_useragent(allow_random_useragent),
	'X_FORWARDED_FOR': random_x_forwarded_for(allow_random_x_forward),
	"Range" : "bytes=0-10240"
	# 'Referer' : 'http://www.google.com',
	# 'Cookie': 'whoami=wyscan_dirfuzz',
}


