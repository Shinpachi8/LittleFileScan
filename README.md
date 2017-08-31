只是修改, 非原创。

将weakfilescan的生成字典模块拿了出来, 然后又在王松_Striker的脚本时把字典拿了出来
自己改了一下误报处理, 不知道效果怎么样
只是为了给扫描器加一个插件


1. 要做的工作:
    - check_404要增加一个type="dir"/"file"的选项
    - 黑名单/白名单可以用lijiejie的，或者直接用404也行

用法:
`--host`:  虽然写成可选，但其实是必选项
`--ext` :  后缀名
`-v`    :  输出详情
`--full`:  使用王松的字典, 会增长时间和误报次数 

```
usage: LittleFileScan.py [-h] [--host HOST] [--ext EXT] [-v] [--full]
                         [-t THREADNUM]

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           the target host, MUST HAVE
  --ext EXT             the extend name, default php
  -v                    show more detail when running
  --full                Use All Dict (May be more False positives and take
                        more time)
  -t THREADNUM, --threadnum THREADNUM
                        the number of thread count, default 15

```