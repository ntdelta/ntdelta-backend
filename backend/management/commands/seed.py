from application.ntdelta.backend.ghidra_integration_lib import open_json_file, get_dll_windindex_content
from django.core.management.base import BaseCommand
import random
import os
import hashlib

from backend.models import WindowsUpdate, DLL, Function, WindowsVersion, DLLInstance


def find_files_with_extension(directory, extension):
    matching_files = []
    for file in os.listdir(directory):
        if file.endswith(extension):
            file_path = os.path.join(directory, file)
            matching_files.append(file_path)
    return matching_files


def seed_data():
    # find all the files in `working_dir` which end in .txt
    extension = ".txt"
    matching_files = find_files_with_extension(os.path.abspath("../../../working_dir"), extension)
    dll_names = [os.path.basename(i).replace(".txt", "") for i in matching_files]
    for DLL_NAME in dll_names:
        working_dir = os.path.abspath("../../worker")
        json_functions = open_json_file(
            working_dir + "\\{}_functions.json".format(DLL_NAME.split(".")[0]))
        json_data = get_dll_windindex_content(DLL_NAME)
        for key, value in json_data.items():
            if 'fileInfo' in value.keys() and 'sha256' in value['fileInfo'].keys():
                # windows versions this hash of the dll is present in
                key_windows_versions = []
                windows_updates_dll_present = []
                for win_ver_key, win_ver_value in value['windowsVersions'].items():
                    windows_version_obj, windows_version_obj_created = WindowsVersion.objects.get_or_create(name=win_ver_key)
                    key_windows_versions.append(windows_version_obj)

                    for win_upd_key in win_ver_value:
                        win_upd_value = win_ver_value[win_upd_key]
                        if 'updateInfo' in win_upd_value.keys():
                            win_upd_obj, win_upd_obj_created = WindowsUpdate.objects.get_or_create(
                                name=win_upd_key,
                                release_date=win_upd_value['updateInfo']['releaseDate'],
                                release_version=win_upd_value['updateInfo']['releaseVersion'],
                                windows_version=windows_version_obj,
                            )
                            windows_updates_dll_present.append(win_upd_obj)

                dll_obj, dll_obj_created = DLL.objects.get_or_create(
                    name=DLL_NAME,
                    description=value['fileInfo']['description'])

                dll_instance_obj, dll_instance_obj_created = DLLInstance.objects.get_or_create(
                    dll=dll_obj,
                    sha256=value['fileInfo']['sha256'],
                    signing_date=value['fileInfo']['signingDate'][0],
                    version=value['fileInfo']['version'],
                    size=value['fileInfo']['size'],
                    virtual_size=value['fileInfo']['virtualSize'],
                )
                [dll_instance_obj.windows_updates.add(j) for j in windows_updates_dll_present]

                #                     windows_versions="models.ManyToManyField(WindowsVersion)",
                #                     functions=json_functions["ghidra" + key],

                for function_name in json_functions['ghidra'+key]:
                    function_decomp_path = os.path.abspath(
                        "../../working_dir") + "\\ghidra" + key + "\\ghidra" + key + "__" + function_name + ".txt"

                    with open(function_decomp_path, 'r', encoding='utf-8') as file:
                        # Read the contents of the file
                        function_c = file.read()
                        function_c_hash = hashlib.md5(function_c.encode('utf-8')).hexdigest()

                    func_obj, func_obj_created = Function.objects.get_or_create(
                        function_name=function_name,
                        function_c=function_c,
                        function_c_hash=function_c_hash,
                        dll_instance=dll_instance_obj
                    )


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


def run_seed(self, mode):
    """ Seed database based on mode

    :param mode: refresh / clear
    :return:
    """
    # Clear data from tables
    clear_data()
    if mode == MODE_CLEAR:
        return

    seed_data()
