# coding: utf-8
import subprocess,os
from xml.dom.minidom import parse
import xml.dom.minidom
import random
import string
import codecs
from models import base_info,vul_info
from celery.decorators import task
from celery.task.schedules import crontab
from celery.decorators import periodic_task
import requests
import datetime


def report_xml(filename,source_path,token):
    DOMTree = xml.dom.minidom.parse(filename)
    Data = DOMTree.documentElement
    ReportSections3 = Data.getElementsByTagName("ReportSection")[2]
    GroupingSections = ReportSections3.getElementsByTagName("GroupingSection")
    num = 1
    for GroupingSection in GroupingSections:
        Issues = GroupingSection.getElementsByTagName("Issue")
        for i in range(len(Issues)):
            groupTitle = GroupingSection.getElementsByTagName("groupTitle")[0].childNodes[0].nodeValue  # 漏洞标题
            #count = GroupingSection.getAttribute('count')  # 漏洞号
            Folder = GroupingSection.getElementsByTagName("Folder")[0].childNodes[0].nodeValue  # 风险
            #Issue_id = Issues[i].getAttribute('iid')  # 问题ID
            Abstract = GroupingSection.getElementsByTagName("Abstract")[i].childNodes[0].nodeValue  # 问题详细
            FileName = GroupingSection.getElementsByTagName("FileName")[i].childNodes[0].nodeValue  # 文件名
            extend = FileName.split('.')[-1] #文件后缀
            FilePath = GroupingSection.getElementsByTagName("FilePath")[i].childNodes[0].nodeValue  # 文件路径
            LineStart = GroupingSection.getElementsByTagName("LineStart")[i].childNodes[0].nodeValue  # 影响行
            Snippet = GroupingSection.getElementsByTagName("Snippet")[i].childNodes[0].nodeValue  # 影响代码
            path = source_path+'/'+FilePath
            with codecs.open(path, "r", encoding='utf-8', errors='ignore') as f:
                full_code = f.read()
            vul_info.objects.create(
                                    vid = num,
                                    title = groupTitle,
                                  risk = Folder,
                                  Abstract = Abstract,
                                  FileName = FileName,
                                  FilePath = FilePath,
                                  LineStart = LineStart,
                                  Snippet = Snippet,
                                  full_code =full_code,
                                  token = token,
                                    extend = extend,
                                  )
            num = num+1
@task
def start(myfile):
    token = ''.join(random.sample(string.ascii_letters + string.digits, 8))
    base_info.objects.create(token=token,name=myfile,)
    '''
    #这段代码是git clone下来的代码，但是现在我改成是upload上传。
    #http://test.com/test.git
    myfile = git.split('/')[-1].split('.')[0]
    try:
        subprocess.check_call('git clone '+git +' /data/fortify/'+myfile,shell=True)
    except subprocess.CalledProcessError as err:
        try:
            subprocess.check_call('cd /data/fortify/' + myfile+' && git pull', shell=True)
        except subprocess.CalledProcessError as err:
            pass
    '''
    #fortify 运行的代码
    source_path = "/data/fortify/"+myfile
    fortify_fpr = "/data/fortify/report/"+myfile+'.fpr'
    fortify_xml = "/data/fortify/report/"+ myfile + '.xml'
    del_fpr = 'sourceanalyzer -b '+myfile+' -clean'
    build = 'sourceanalyzer  -b '+ myfile +' -Xmx1200M -Xms600M -Xss24M     -source 1.8 -machine-output   '+source_path
    scan = 'sourceanalyzer  -b '+ myfile + ' -scan  -format fpr -f '+fortify_fpr+' -machine-output '
    report = 'ReportGenerator  -format xml -f '+fortify_xml+' -source '+fortify_fpr+' -template DeveloperWorkbook.xml'
    subprocess.check_call(del_fpr,shell=True)
    subprocess.check_call(build, shell=True)
    subprocess.check_call(scan, shell=True)
    subprocess.check_call(report, shell=True)
    report_xml(fortify_xml,source_path,token)
    base_info.objects.filter(token=token).update(total=len(vul_info.objects.filter(token=token)))


