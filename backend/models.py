from django.db import models
from django.db.models import Q

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

    def get_oldest_windows_update(self):
        updates = self.windows_updates.order_by('release_date')
        return updates.first() if updates.exists() else None

    def get_first_seen(self):
        """
        This function tries to use the signing date. If it is not
        set, it will default to the date of the first update it is
        part of.
        """
        if str(self.signing_date) == '1970-01-01 00:00:00+00:00':
            oldest_windows_update = self.get_oldest_windows_update()
            if oldest_windows_update:
                return oldest_windows_update.release_date

        return self.signing_date

    def is_insider(self):
        """
        Was this DLL taken from insider preview?
        """
        # Use Q objects to filter names starting with "KB" or "BASE"
        updates = self.windows_updates.filter(Q(name__startswith="KB") | Q(name__startswith="BASE"))
        # If any such updates are found, it means the DLL is not from an insider preview
        if updates.exists():
            return False
        # Otherwise, it's potentially from an insider preview
        return True

    def __str__(self):
        return self.sha256


class Function(models.Model):
    dll_instance = models.ForeignKey(DLLInstance, on_delete=models.CASCADE)
    function_name = models.CharField(max_length=100)
    function_c = models.TextField()
    function_c_hash = models.CharField(max_length=70)

    def __str__(self):
        return self.function_name
