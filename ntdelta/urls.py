"""
URL configuration for ntdelta project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
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
from backend import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/dlls', views.dlls),
    path('api/dlls/instances/<int:dll_instance_id>/functions', views.dll_functions),
    path('api/dlls/instances/<int:dll_instance_id>', views.dll),
    path('api/dlls/instances/sha256', views.get_dll_instance_by_sha256),
    path('api/dlls/<str:dll_name>', views.list_dlls_by_name),
    path('api/dlls/<str:dll_name>/diffs', views.get_dll_function_diffs),
    path('api/windows_versions', views.windows_versions),
    path('api/windows_updates', views.windows_updates),
    path('api/functions', views.functions),
    path('api/functions/<int:function_id>', views.function),
    path('api/patches/', views.patch_list, name='patch-list'),
    path('api/patch/<int:id>', views.patch_detail, name='patch-detail'),
    path('api/functions/search', views.search_functions_by_name, name='search_functions'),
]
