import json


def open_json_file(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)
        return data


def get_dll_windindex_content(dll_name):
    winbindex_ci_dll_json = "C:\\Users\\Administrator\\ntdelta\\working_dir\\{}.txt".format(dll_name)
    return open_json_file(winbindex_ci_dll_json)



