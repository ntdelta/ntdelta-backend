from django.contrib import admin
from .models import DLL, DLLInstance, WindowsUpdate, WindowsVersion, Function


class DllInstanceAdminInline(admin.TabularInline):
    def has_change_permission(self, request, obj=None):
        return False

    model = DLLInstance
    can_delete = False


class FunctionAdminInline(admin.TabularInline):
    model = Function
    can_delete = False

    def has_change_permission(self, request, obj=None):
        return False


class DLLAdmin(admin.ModelAdmin):
    inlines = (DllInstanceAdminInline,)
    list_display = ("name", "description")


class DLLInstanceAdmin(admin.ModelAdmin):
    def function_count(self, obj):
        return obj.function_set.count()

    inlines = (FunctionAdminInline,)
    list_display = ("sha256", "dll", "function_count", "version")
    list_filter = ["dll"]


class FunctionAdmin(admin.ModelAdmin):
    list_display = ("function_name", "dll_instance")


class WindowsUpdateAdmin(admin.ModelAdmin):
    list_display = ("name", "release_version", "windows_version")


class WindowsVersionAdmin(admin.ModelAdmin):
    list_display = ["name"]


admin.site.register(DLL, DLLAdmin)
admin.site.register(DLLInstance, DLLInstanceAdmin)
admin.site.register(WindowsUpdate, WindowsUpdateAdmin)
admin.site.register(WindowsVersion, WindowsVersionAdmin)
admin.site.register(Function, FunctionAdmin)
