from django.core.management.base import BaseCommand
from django.db import models

from backend.models import Function, DLLInstance

class Command(BaseCommand):
    help = ('Deletes DLLInstances associated with more than 20 FUN_ functions. Useful for finding examples where we '
            'could not find symbols.')

    def handle(self, *args, **options):
        # Get a list of DLLInstance IDs that have more than 20 FUN_ functions
        dll_instance_ids_to_delete = Function.objects.filter(function_name__startswith='FUN_')\
            .values('dll_instance').annotate(count_functions=models.Count('dll_instance'))\
            .filter(count_functions__gt=15).values_list('dll_instance', flat=True)

        # Delete the DLLInstance objects with the associated IDs
        deleted_count, _ = DLLInstance.objects.filter(id__in=dll_instance_ids_to_delete).delete()

        self.stdout.write(self.style.SUCCESS(f'Successfully deleted {deleted_count} DLLInstances with more than 20 FUN_ functions.'))