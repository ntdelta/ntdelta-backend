from application.ntdelta.backend.ghidra_integration_lib import open_json_file, get_dll_windindex_content
from django.core.management.base import BaseCommand
import random
import os
import hashlib

from backend.models import WindowsUpdate, DLL, Function, WindowsVersion, DLLInstance
"""

This is because you didn't add the updates during a POST after decomp

"""

# python manage.py seed --mode=refresh

""" Clear all data and creates addresses """
MODE_REFRESH = 'refresh'

""" Clear all data and do not create any object """
MODE_CLEAR = 'clear'


class Command(BaseCommand):
    help = "seed database for testing and development."

    def add_arguments(self, parser):
        parser.add_argument('--mode', type=str, help="Mode")

    def handle(self, *args, **options):
        self.stdout.write('seeding data...')
        run_seed(self, options['mode'])
        self.stdout.write('done.')


def clear_data():
    """Deletes all the table data"""
    print("lets delete some stuff")
    # Address.objects.all().delete()

import json


def run_seed(self, mode):
    """ Seed database based on mode

    :param mode: refresh / clear
    :return:
    """
    # Clear data from tables
    clear_data()
    if mode == MODE_CLEAR:
        return

    with open('C:\\Users\\Administrator\\Downloads\\rawdogjson\\rawdogjson', 'r', encoding="utf-8") as json_file:
        json_values = json.load(json_file)
        for hash, data in json_values.items():
            instance = DLLInstance.objects.filter(sha256=hash)
            if len(instance) > 0:
                print(instance)
                instance = instance.first()
                for version, updates in data['windowsVersions'].items():
                    print(version)
                    for update_name, update_data in updates.items():
                        print(update_name)
                        if 'updateInfo' in update_data.keys():
                            win_update = WindowsUpdate.objects.filter(release_version=update_data['updateInfo']['releaseVersion'])
                            if len(win_update) > 0:
                                win_update = win_update.first()
                                print(update_data['updateInfo']['releaseDate'])
                                print(update_data['updateInfo']['releaseVersion'])
                                if not instance.windows_updates.filter(id=win_update.id).exists():
                                    print("lets add")
                                    instance.windows_updates.add(win_update)
                        elif 'windowsVersionInfo' in update_data.keys():
                            win_update = WindowsUpdate.objects.filter(
                                release_date=update_data['windowsVersionInfo']['releaseDate'],
                                release_version="BASE"
                            )
                            if len(win_update) > 0:
                                win_update = win_update.first()
                                print(update_data['windowsVersionInfo']['releaseDate'])
                                print("BASE")
                                if not instance.windows_updates.filter(id=win_update.id).exists():
                                    print("lets add")
                                    instance.windows_updates.add(win_update)


