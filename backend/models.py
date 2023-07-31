from django.db import models


class WindowsVersion(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.name}"


class WindowsUpdate(models.Model):
    name = models.CharField(max_length=100)
    release_date = models.CharField(max_length=100)
    release_version = models.CharField(max_length=100)
    windows_version = models.ForeignKey(WindowsVersion, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.name}"


class DLL(models.Model):
    name = models.CharField(max_length=128)
    description = models.CharField(max_length=248)

    def get_windows_versions(self):
        update_list = list(self.dllinstance_set.values_list('windows_updates__windows_version__name',
                                                            'windows_updates__windows_version__id').distinct())
        return [{"version": item[0], "id": item[1]} for item in update_list]

    def __str__(self):
        return f"{self.name}"


class DLLInstance(models.Model):
    dll = models.ForeignKey(DLL, on_delete=models.CASCADE)
    sha256 = models.CharField(max_length=64)
    signing_date = models.DateTimeField()

    # what updates was it present for?
    windows_updates = models.ManyToManyField(WindowsUpdate)
    version = models.CharField(max_length=20)
    size = models.IntegerField()
    virtual_size = models.IntegerField()

    def __str__(self):
        return self.sha256


class Function(models.Model):
    dll_instance = models.ForeignKey(DLLInstance, on_delete=models.CASCADE)
    function_name = models.CharField(max_length=100)
    function_c = models.TextField()
    function_c_hash = models.CharField(max_length=70)

    def __str__(self):
        return self.function_name
