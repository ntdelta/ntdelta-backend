import base64
from django.http import JsonResponse, HttpResponse
from distutils.version import LooseVersion
from django.forms.models import model_to_dict
from backend.models import WindowsUpdate, DLL, Function, WindowsVersion, DLLInstance
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import json
import datetime


def get_version_as_date_backup(values_dict):
    if str(values_dict["first_seen_date"]) == '1970-01-01 00:00:00+00:00':
        oldest_windows_update = DLLInstance.objects.get(id=values_dict["id"]).get_oldest_windows_update()
        if oldest_windows_update:
            values_dict["first_seen_date"] = oldest_windows_update.release_date


def order_dlls_by_version(name):
    dll_instances = DLLInstance.objects.filter(dll__name=name)
    sorted1 = sorted(dll_instances, key=lambda obj: LooseVersion(obj.version.split(" ")[0]))
    return sorted1


def get_next_dll(dlls, dll_id):
    index = 0
    for dll in dlls:
        if dll.id == dll_id:
            if len(dlls) == (index + 1):
                return dlls[0]
            else:
                return dlls[index + 1]
        index += 1


def get_previous_dll(dlls, dll_id):
    index = 0
    for dll in dlls:
        if dll.id == dll_id:
            return dlls[index - 1]
        index += 1


@csrf_exempt
@cache_page(60 * 60 * 24)  # Cache for a day
def dlls(request):
    if request.method == 'POST':
        auth_header = request.META.get('HTTP_AUTHORIZATION')

        # Check if the Authorization header is present and starts with 'Basic '
        if auth_header and auth_header.startswith('Basic '):
            # Remove the 'Basic ' prefix and decode the base64-encoded username:password string
            auth_data = auth_header[len('Basic '):]
            username, password = base64.b64decode(auth_data).decode().split(':', 1)

            # Now you have the username and password, you can perform your authentication logic here.
            # For simplicity, let's just print them in this example:
            if username == settings.API_USERNAME and password == settings.API_PASSWORD:
                print(f"Username: {username}, Password: {password}")

                # Your authentication logic goes here.
                # You can use Django's built-in authentication system or any other custom logic.

                # If authentication is successful, return the response.
                post_data = json.loads(request.body)
                name = post_data['name']
                description = post_data['description']

                # Try to retrieve an existing object by name
                dll_obj = DLL.objects.filter(name=name).first()

                if dll_obj:
                    # An object with the given name exists, update description if needed
                    if dll_obj.description != description:
                        dll_obj.description = description
                        dll_obj.save()
                else:
                    # No object with the given name, create a new one
                    dll_obj = DLL.objects.create(name=name, description=description)

                instance_windows_updates = []
                # if the key in post_data['update_info'] is 'builds' then it is an insider preview DLL
                if 'builds' in post_data['update_info'].keys():
                    windows_version_obj, _ = WindowsVersion.objects.get_or_create(
                        name="IP"  # IP - Insider Preview
                    )

                    for _, build in post_data['update_info']['builds'].items():
                        release_date = datetime.datetime.fromtimestamp(build['updateInfo']['created'])
                        windows_update_obj, _ = WindowsUpdate.objects.get_or_create(
                            name="IP{}".format(build["updateInfo"]["build"]),
                            release_date=release_date,
                            release_version=build['updateInfo']['build'],
                            windows_version=windows_version_obj,
                        )
                        instance_windows_updates.append(windows_update_obj)

                else:
                    for windows_version, windows_update in post_data['update_info'].items():
                        windows_version_obj, _ = WindowsVersion.objects.get_or_create(
                            name=windows_version
                        )

                        for a, b in windows_update.items():
                            if 'updateInfo' in b.keys():
                                release_date = b['updateInfo']['releaseDate']

                                windows_update_obj, _ = WindowsUpdate.objects.get_or_create(
                                    name=a,
                                    release_date=release_date,
                                    release_version=b['updateInfo']['releaseVersion'],
                                    windows_version=windows_version_obj,
                                )
                            elif 'windowsVersionInfo' in b.keys():
                                windows_update_obj, _ = WindowsUpdate.objects.get_or_create(
                                    name=a,
                                    release_date=b['windowsVersionInfo']['releaseDate'],
                                    release_version='BASE',
                                    windows_version=windows_version_obj,
                                )
                            instance_windows_updates.append(windows_update_obj)

                dll_instance_object, _ = DLLInstance.objects.get_or_create(
                    dll=dll_obj,
                    sha256=post_data['sha256'],
                    signing_date=post_data['signing_date'],
                    version=post_data['version'],
                    size=post_data['size'],
                    virtual_size=post_data['virtual_size'],
                )

                dll_instance_object.windows_updates.set(instance_windows_updates)

                for function_name, function_data in post_data['functions'].items():
                    Function.objects.get_or_create(
                        dll_instance=dll_instance_object,
                        function_name=function_name,
                        function_c=function_data['function_c'],
                        function_c_hash=function_data['function_c_hash'],
                    )

                return JsonResponse({"bosh": 1}, safe=False, json_dumps_params={'indent': 2})
            else:
                # Login failed
                return HttpResponse("Unauthorized", status=401)
        # If the header is missing or not in the correct format, return a 401 Unauthorized response.
        return HttpResponse("Unauthorized", status=401)


    else:
        queryset = DLL.objects.values_list('name', flat=True)
        dll_names = list(set(list(queryset)))
        response_json = {}
        for dll_name in dll_names:
            ordered_dlls = order_dlls_by_version(dll_name)

            if len(ordered_dlls) >= 2:
                first_dll = ordered_dlls[0]
                last_dll = ordered_dlls[-1]
                first_dll_dict = model_to_dict(first_dll)
                last_dll_dict = model_to_dict(last_dll)

                # convert dll windows updates to dict too
                first_dll_dict['windows_updates'] = [model_to_dict(t) for t in first_dll.windows_updates.all()]
                last_dll_dict['windows_updates'] = [model_to_dict(t) for t in last_dll.windows_updates.all()]

                dll_instances = DLLInstance.objects.filter(
                    dll=DLL.objects.get(name=dll_name)
                )

                function_count = Function.objects.filter(
                    dll_instance__in=dll_instances  # could be any of these dll instances
                ).count()

                versions = order_dlls_by_version(dll_name)
                versions_dict = [{
                    "id": version.id,
                    "first_seen_date": version.get_first_seen(),
                    "version": version.version,
                    "insider": True if (version.windows_updates.first().name[0:2] == "IP") else False
                }
                    for
                    version in versions]

                response_json[dll_name] = {
                    "first_dll": first_dll_dict,
                    "last_dll": last_dll_dict,
                    "function_count": function_count,
                    "count": DLLInstance.objects.filter(
                        dll__name=dll_name
                    ).count(),
                    "version_map": versions_dict,
                    "windows_versions": DLL.objects.get(name=dll_name).get_windows_versions(),
                }

            else:
                response_json[dll_name] = {
                    "function_count": 0,
                    "count": DLLInstance.objects.filter(
                        dll__name=dll_name
                    ).count(),
                }

        return JsonResponse(response_json, safe=False, json_dumps_params={'indent': 2})


def list_dlls_by_name(request, dll_name):
    queryset = DLLInstance.objects.filter(dll__name=dll_name)

    queryset_values = queryset.values('id',
                                      'signing_date',
                                      'version',
                                      'size',
                                      'virtual_size',
                                      'sha256')

    data = list(queryset_values)
    data = sorted(data, key=lambda obj: LooseVersion(obj["version"].split(" ")[0]))
    counter = 0
    for i in data:
        i["function_count"] = function_count = Function.objects.filter(
            dll_instance=queryset[counter]  # could be any of these dll instances
        ).count()
        i["insider"] = True if (
                    DLLInstance.objects.get(pk=i["id"]).windows_updates.first().name[0:2] == "IP") else False
        i["windows_updates"] = list(queryset[counter].windows_updates.values(
            "id",
            "name",
            "release_date",
            "windows_version__name",
        ))

        # If the singing date field in the PE is used for hashing then we can get
        # first seen from the oldest Windows update it was contained in.
        i["first_seen_date"] = i["signing_date"]
        del i["signing_date"]

        get_version_as_date_backup(i)

        counter += 1

    wrapper_json = {
        "instances": data,
        "dll": model_to_dict(DLL.objects.get(name=dll_name))
    }
    return JsonResponse(wrapper_json, safe=False, json_dumps_params={'indent': 2})


@cache_page(60 * 60 * 24)  # Cache for a day
def functions(request):
    queryset = Function.objects.values('dll_instance',
                                       'function_name',
                                       'function_c',
                                       'function_c_hash')[:10]
    data = list(queryset)
    return JsonResponse(data, safe=False, json_dumps_params={'indent': 2})


@cache_page(60 * 60 * 24)  # Cache for a day
def windows_versions(request):
    queryset = WindowsVersion.objects.values('name')
    data = list(queryset)
    return JsonResponse(data, safe=False, json_dumps_params={'indent': 2})


@cache_page(60 * 60 * 24)  # Cache for a day
def windows_updates(request):
    queryset = WindowsUpdate.objects.values(
        'name',
        'release_date',
        'release_version',
        'windows_version',
    )
    data = list(queryset)
    return JsonResponse(data, safe=False, json_dumps_params={'indent': 2})


@cache_page(60 * 60 * 24)  # Cache for a day
def dll_functions(request, dll_instance_id):
    queryset = Function.objects.filter(
        dll_instance_id=dll_instance_id
    ).values('dll_instance',
             'function_name',
             'id',
             'function_c',
             'function_c_hash')
    data = list(queryset)
    return JsonResponse(data, safe=False, json_dumps_params={'indent': 2})


@cache_page(60 * 60 * 24)  # Cache for a day
def function(request, function_id):
    obj = Function.objects.get(
        id=function_id
    )
    dict_obj = model_to_dict(obj)
    next_dll = get_next_dll(order_dlls_by_version(obj.dll.name), obj.dll.id)
    dll_dict = model_to_dict(next_dll)
    dict_obj["next_dll"] = {
        "id": dll_dict["id"],
        "version": dll_dict["version"],
        "first_seen_date": str(dll_dict["signing_date"]),
        "sha256": dll_dict["sha256"],
        "description": dll_dict["description"],
    }
    return JsonResponse(dict_obj, safe=False, json_dumps_params={'indent': 2})


@cache_page(60 * 60 * 24)  # Cache for a day
def dll(request, dll_instance_id):
    obj = DLLInstance.objects.get(
        id=dll_instance_id
    )

    root_obj = DLL.objects.get(
        id=obj.dll.id
    )

    dict_obj = model_to_dict(obj)
    next_dll = get_next_dll(order_dlls_by_version(root_obj.name), obj.id)
    prev_dll = get_previous_dll(order_dlls_by_version(root_obj.name), obj.id)
    next_dict_obj = model_to_dict(next_dll)
    prev_dict_obj = model_to_dict(prev_dll)

    updates = []
    for update in dict_obj['windows_updates']:
        updates.append(
            {
                "id": update.id,
                "name": update.name,
                "release_date": update.release_date,
                "windows_version__name": update.windows_version.name,
            }
        )

    del dict_obj['windows_updates']
    del next_dict_obj['windows_updates']
    del prev_dict_obj['windows_updates']

    dict_obj['windows_updates'] = updates
    dict_obj['next_dll'] = next_dict_obj
    dict_obj['prev_dll'] = prev_dict_obj
    dict_obj['dll'] = model_to_dict(root_obj)
    dict_obj['function_count'] = Function.objects.filter(
        dll_instance=obj
    ).count()

    # If the singing date field in the PE is used for hashing then we can get
    # first seen from the oldest Windows update it was contained in.
    dict_obj["first_seen_date"] = dict_obj["signing_date"]
    del dict_obj["signing_date"]

    get_version_as_date_backup(dict_obj)

    return JsonResponse(dict_obj, safe=False, json_dumps_params={'indent': 2})
