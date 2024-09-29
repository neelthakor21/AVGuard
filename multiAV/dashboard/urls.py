from django.contrib import admin
from django.urls import path, include
from dashboard import views

urlpatterns = [
    path('', views.index, name='home'),
    path('login', views.loginUser, name='login'),
    path('logout', views.logoutUser, name='logout'),
    path('upload', views.upload, name='upload'),
    path('dashboard', views.dashboard, name='dashboard')
]