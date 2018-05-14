# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
import datetime



class base_info(models.Model):
    name = models.CharField(max_length=100)    #项目名字
    token = models.CharField(max_length=50)     #项目标识
    git = models.CharField(max_length=100,null=True,blank=True)      #git地址
    total = models.CharField(max_length=10,default='0',null=True) #该项目漏洞总数
    time = models.DateTimeField(default=datetime.datetime.now()) #扫描时间
    #time = models.DateTimeField(default=datetime.datetime.now().strftime('%Y-%m-%d'))


class vul_info(models.Model):
    vid = models.CharField(max_length=10)        #用来辨别每个页面的id
    title = models.CharField(max_length=200)       #漏洞名称
    risk = models.CharField(max_length=10)        #漏洞风险
    Abstract = models.TextField()                 #漏洞原因
    FileName = models.CharField(max_length=50)      #文件名
    FilePath = models.CharField(max_length=200)     #文件位置
    LineStart = models.CharField(max_length=10)     #影响行
    Snippet = models.TextField()         #影响行的代码
    full_code = models.TextField()         #全部的代码
    extend = models.CharField(max_length=50)     #后缀名
    token = models.CharField(max_length=50)      #项目标识
    time = models.DateTimeField(default=datetime.datetime.now())     #扫描时间
