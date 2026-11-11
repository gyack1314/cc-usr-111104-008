"""WARC 1.1归档器、独立校验器与只读回放。

只依赖Python标准库。采集器(:mod:`archive_lab.archiver`)、校验器
(:mod:`archive_lab.validator`)与回放(:mod:`archive_lab.replay`)互相不依赖
对方的内存状态，共用的:mod:`archive_lab.warc`只处理WARC帧格式本身。
"""
