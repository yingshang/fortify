"""fortify URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from aduit import views
urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^start/',views.fortify_git),#这个函数是批量扫描gitlab
    url(r'^$',views.projects),#查看项目
    url(r'^overview/',views.overview),#查看概要
    url(r'^report/',views.report),#查看报告
    url(r'^api/list',views.list),#查看报告清单
    url(r'^api/detail',views.detail),#查看详情
    url(r'^api/start',views.api_start),#对单个项目进行扫描
    url(r'^api/del',views.api_del),#对单个项目进行删除
    url(r'^uploadFile',views.upload_file)#上传项目进行扫描
]
