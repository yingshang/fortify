# coding: utf-8
from django.shortcuts import render
from django.http import  JsonResponse,HttpResponseRedirect
from django.http.response import HttpResponse
from models import base_info,vul_info
import time,datetime
from info import information
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth import  login as auth_login
from django.contrib.auth import authenticate
import calendar
from django.db.models import Count
import requests,os
from django.db.models import Q
from fortify_run import start
# Create your views here.

#该函数是统计漏洞，后来想想直接发到禅道就算了，就没写
def overview(request):
    # time type
    date = datetime.datetime.now()
    c_month = int(date.strftime('%m'))
    c_day = int(date.strftime('%d'))
    c_year = int(date.strftime('%Y'))
    c_quarter = 0
    day_first = ''
    day_last = ''
    c_quarter_first = 0
    c_quarter_last = 0
    if c_month in [1, 2, 3]:
        c_quarter = 1
        c_quarter_first = 1
        c_quarter_last = 3
    elif c_month in [4, 5, 6]:
        c_quarter = 2
        c_quarter_first = 4
        c_quarter_last = 6
    elif c_month in [7, 8, 9]:
        c_quarter = 3
        c_quarter_first = 7
        c_quarter_last = 9
    elif c_month in [10, 11, 12]:
        c_quarter = 4
        c_quarter_first = 10
        c_quarter_last = 12

    # time type
    month = request.GET.get('month')
    time_type = request.GET.get('type')
    if time_type not in ['w', 'm', 'q', 'a']:
        # default tt
        time_type = 'w'
    # calculate first day/last day and VT's x axis data
    c_mark = '#'
    trend_scan = {
        'file': [],
        'line': [],
        'project': [],
        'task': []
    }
    amount_vulnerability = {
        'new': {
            'total': 0,
            'time_type': 0
        },
        'fixed': {
            'total': 0,
            'time_type': 0
        }
    }
    # Vulnerability Trend (VT)
    vt_x = []
    if time_type == 'm':
        p_month = 0
        if month is None:
            p_month = int(time.strftime('%m', time.localtime()))
        elif int(month) <= 12:
            p_month = int(month)

        current_time = time.strftime('%Y-{month}-{day}', time.localtime())
        day_first = current_time.format(month=p_month, day=1)
        day_last = current_time.format(month=p_month, day=31)

        for month in range(1, 13):
            x_time = '{month}月'.format(month=month)
            c_year = int(time.strftime('%Y', time.localtime()))
            start = '{year}-{month}-{day}'.format(year=c_year, month=month, day=1)
            next_month = datetime.date(c_year, month, 1).replace(day=28) + datetime.timedelta(days=4)
            end = next_month - datetime.timedelta(days=next_month.day)

            vt_x.append({
                'time': x_time,
                'data': '0'
            })

    elif time_type == 'q':
        for q in range(1, 5):
            x_time = 'Q{quarter}'.format(quarter=q)
            s_month = 0
            e_month = 0
            if q == 1:
                s_month = 1
                e_month = 3
            elif q == 2:
                s_month = 4
                e_month = 6
            elif q == 3:
                s_month = 7
                e_month = 9
            elif q == 4:
                s_month = 10
                e_month = 12

               
            cm, last_day = calendar.monthrange(c_year, e_month)
            start = '{year}-{month}-{day}'.format(year=c_year, month=s_month, day=1)
            end = '{year}-{month}-{day}'.format(year=c_year, month=e_month, day=last_day)
            vt_x.append({
                'time': x_time,
                'data': '0'
            })
        cm, last_day = calendar.monthrange(c_year, c_quarter_last)
        day_first = '{0}-{1}-{2}'.format(c_year, c_quarter_first, 1)
        day_last = '{0}-{1}-{2}'.format(c_year, c_quarter_last, last_day)
    else:
        # default TT(time type): w(weekly)
        week_desc = {
            0: '日',
            1: '一',
            2: '二',
            3: '三',
            4: '四',
            5: '五',
            6: '六'
        }
        for d in range(-7, 1):
            t = time.localtime(time.time() + (d * 86400))
            if d == -7:
                day_first = time.strftime('%Y-%m-%d', t)
            if d == 0:
                day_last = time.strftime('%Y-%m-%d', t)
            week = int(time.strftime('%w', t))
            week_d = week_desc[week]
            month = int(time.strftime('%m', t))
            day = int(time.strftime('%d', t))
            if day == c_day:
                x_time = '{0}{1}/{2}({3})'.format(c_mark, month, day, week_d)
            else:
                x_time = '{0}/{1}({2})'.format(month, day, week_d)
            # VT x data
            localtime = time.localtime(time.time() + (d * 86400))
            start_end = time.strftime('%Y-%m-%d', localtime)

            vt_x.append({
                'time': x_time,
                'data': '0'
            })
        if time_type == 'a':
            day_first = '1997-10-10'
            day_last = time.strftime('%Y-%m-%d', time.localtime())

    return render(request,'backend/index/overview.html',locals())

def fortify_git(request):
    #这里需要在jenkins调用需要发包的git项目写成json调用或者直接在gitlab抓取作JSON调用
    r = requests.get('http://XXXX')
    git_list = r.json()['back_gitlab_url']
    list = []
    for i in git_list:
        #输入用户名和密码
        list.append(i.replace('http://','http://XXXXX%40XXXX:XXXXX@'))
    for git in  list:
        start.delay(git)
    return HttpResponse('success')

def projects(request):
    keyword = request.GET.get('keyword')
    if (keyword==None) or (len(keyword)==0):
        infos = base_info.objects.all()
    else:
        infos = base_info.objects.filter(name__contains=keyword)
    return  render(request,'backend/project/projects.html',locals())




def results(request):
    token = request.GET.get('token')
    results = vul_info.objects.filter(token=token)
    low = len(results.filter(risk='low'))
    Medium = len(results.filter(risk='Medium'))
    High = len(results.filter(risk='High'))
    Critical = len(results.filter(risk='Critical'))
    return render(request,'result.html',locals())

def issue(request):
    id = request.GET.get('id')
    results = vul_info.objects.get(id=id)
    info = information(results.title)
    full_code = results.full_code
    describe = info['describe']
    Recommendation = info['Recommendation']
    vul_title = info['vul_title']
    return render(request, 'issue.html', locals())


def report(request):
    t = request.GET.get('t')
    token = request.GET.get('token')
    information = base_info.objects.get(token=token)
    report_name = information.name
    scan_time = information.time
    vuls = vul_info.objects.values('title').annotate(Count('title'))       #所有漏洞标题
    critical_title = vul_info.objects.filter(token=token).filter(Q(risk='Critical') | Q(risk = 'High')).values('title').annotate(Count('title'))  #严重和高危漏洞标题
    #vul_title = vul_info.objects.filter(token=token).values('title').annotate(Count('title'))  # 所有漏洞标题
    risks = vul_info.objects.filter(token=token).values('risk').annotate(Count('risk'))
    low_risk = 0
    Medium_risk = 0
    High_risk = 0
    Critical_risk = 0
    for i in range(len(risks)):
        if risks[i]['risk']=='Low':
            low_risk = risks[i]['risk__count']
        if risks[i]['risk']=='Medium':
            Medium_risk = risks[i]['risk__count']
        if risks[i]['risk']=='High':
            High_risk = risks[i]['risk__count']
        if risks[i]['risk']=='Critical':
            Critical_risk = risks[i]['risk__count']
    return render(request,'report.html',locals())

@csrf_exempt
def list(request):
    if request.method == 'POST':
        token = request.POST.get('token')
        result1 = vul_info.objects.filter(token=token)
        r = vul_info.objects.values('title').distinct()
        rule_filter = []
        for i in r:
            rule_filter.append(i['title'])
        vul_information = []

        for vul in result1:
            vul_information.append({
                'line_number':vul.LineStart,
                'file_path':vul.FilePath,
                'level':vul.risk,
                'rule_name':vul.title,
                'language':vul.extend,
                'describe':information(vul.title)['describe'],
                'Recommendation':information(vul.title)['Recommendation'],
            })

        return JsonResponse({
            'code': 1001,
            'result': {
                'scan_data': {'extension': 21,
                              'language': 'php',
                              'trigger_rules': 12,
                              'vulnerabilities': vul_information,
                              'target_directory': '',
                              'push_rules': 12,
                              'framework': 'unkonw',
                              'file': 213
                              },
                'rule_filter': rule_filter,
            }},safe=False)
    else:
        return HttpResponse('must be post method ')

@csrf_exempt
def detail(request):
    token = request.POST.get('token')
    vid = request.POST.get('vid')
    code = vul_info.objects.filter(token=token).get(vid=vid).full_code
    extend = vul_info.objects.filter(token=token).get(vid=vid).extend
    return JsonResponse({
        'code':1001,
        'result':{
            'file_content':code,
            'extension':extend,
        }
    })

@csrf_exempt
def api_start(request):
    token = request.POST.get('token')
    git_url = base_info.objects.get(token=token).git
    start(git_url)
    return JsonResponse({
        'code':1001,
        'result':'新增成功'
    })

@csrf_exempt
def api_del(request):
    token = request.POST.get('token')
    base_info.objects.filter(token=token).delete()
    vul_info.objects.filter(token=token).delete()
    return JsonResponse({
        'code': 1001,
        'result': '删除成功'
    })


@csrf_exempt
def upload_file(request):
    if request.method == "POST":
        myFile =request.FILES.get("myfile", None)
        name = myFile.name
        if not myFile:
            return HttpResponse("no files for upload!")
        elif myFile.name.split('.')[1] != 'zip':
            return HttpResponse("upload file must be zip")
        else:
            destination = open(os.path.join("/data/fortify/",myFile.name),'wb+')
            for chunk in myFile.chunks():
                destination.write(chunk)
            destination.close()
            print(name)
            os.system("unzip /data/fortify/"+myFile.name+"  -d  /data/fortify/")
            start(name.split('.')[0])
            return HttpResponse("upload over!")
    else:
        return render(request, "upload.html", locals())
