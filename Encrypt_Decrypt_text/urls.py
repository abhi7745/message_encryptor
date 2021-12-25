"""Encrypt_Decrypt_text URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

import main_app.views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', main_app.views.index,name='index_url'),

    path('encrypt/', main_app.views.encrypt,name='encrypt_url'),
    path('decrypt/', main_app.views.decrypt,name='decrypt_url'),

    
    path('encrypt2/', main_app.views.encrypt2,name='encrypt2_url'),
    path('decrypt2/', main_app.views.decrypt2,name='decrypt2_url'),
]
