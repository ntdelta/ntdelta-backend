import json
import os

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from backend.models import DLLInstance, Function, Patch, PatchFunctionRelation


class Command(BaseCommand):
    help = 'Creates a Patch object with associated Function objects based on static JSON data.'
    with open(os.getcwd() + '/backend/management/commands/patches.json', 'r') as file_handle:
        data = file_handle.read()

    def handle(self, *args, **options):
        with transaction.atomic():
            # Delete all PatchFunctionRelation objects
            self.stdout.write(self.style.NOTICE('Deleting all PatchFunctionRelation objects...'))
            PatchFunctionRelation.objects.all().delete()

            # Delete all Patch objects
            self.stdout.write(self.style.NOTICE('Deleting all Patch objects...'))
            Patch.objects.all().delete()
        try:
            parsed_data_objects = json.loads(self.data)
        except json.JSONDecodeError as e:
            raise CommandError(f"Error decoding JSON: {e}")

        for parsed_data in parsed_data_objects["patches"]:
            try:
                pre_patch_dll_instance = DLLInstance.objects.get(sha256=parsed_data['pre_patch_dll_instance_hash'])
                post_patch_dll_instance = DLLInstance.objects.get(sha256=parsed_data['post_patch_dll_instance_hash'])
            except DLLInstance.DoesNotExist:
                raise CommandError('One of the DLLInstances with the specified hashes does not exist.')

            patch_data = parsed_data['patch']
            patch = Patch.objects.create(
                name=patch_data['name'],
                description=patch_data['description'],
                url=patch_data['url'],
                pre_patch_dll_instance=pre_patch_dll_instance,
                post_patch_dll_instance=post_patch_dll_instance
            )

            for func_data in parsed_data['functions']:
                dll_instance = pre_patch_dll_instance if func_data['flag'] == 'pre' else post_patch_dll_instance
                try:
                    function = Function.objects.get(function_name=func_data['name'], dll_instance=dll_instance)
                    PatchFunctionRelation.objects.create(
                        patch=patch,
                        function=function,
                        title=func_data['title'],
                        description=func_data['description']
                    )
                except Function.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING(f'Function "{func_data["name"]}" not found for the provided DLLInstance.'))

            self.stdout.write(self.style.SUCCESS(f'Successfully created patch "{patch.name}" with associated functions.'))
