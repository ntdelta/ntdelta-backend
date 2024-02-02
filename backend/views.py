import base64
from django.core import serializers
from django.http import JsonResponse, HttpResponse
from distutils.version import LooseVersion
from backend.models import WindowsUpdate, DLL, Function, WindowsVersion, DLLInstance
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import json
import datetime
from django.forms.models import model_to_dict
from django.db.models import Prefetch, Count
from django.views.decorators.http import require_http_methods


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
                    "insider": version.is_insider()
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
    try:
        dll = DLL.objects.get(name=dll_name)
    except DLL.DoesNotExist:
        return JsonResponse({"error": "DLL not found"}, status=404)

    # Pre-fetch related 'windows_updates' and their related 'windows_version'.
    windows_updates_prefetch = Prefetch('windows_updates',
                                        queryset=WindowsUpdate.objects.all().prefetch_related('windows_version'))

    # Fetch DLLInstances with prefetch_related for optimization.
    dll_instances = DLLInstance.objects.filter(
        dll=dll
    ).prefetch_related(
        windows_updates_prefetch
    ).annotate(
        function_count=Count('function__id'),  # Count the functions related to the DLLInstance
    )

    data = []
    for instance in dll_instances:
        windows_updates = [{
            "id": wu.id,
            "name": wu.name,
            "release_date": wu.release_date,
            "windows_version__name": wu.windows_version.name,
        } for wu in instance.windows_updates.all()]

        data.append({
            'id': instance.id,
            'signing_date': instance.signing_date,
            'version': instance.version,
            'size': instance.size,
            'virtual_size': instance.virtual_size,
            'sha256': instance.sha256,
            'function_count': instance.function_count,
            'insider': instance.is_insider(),
            'windows_updates': windows_updates,
            'first_seen_date': instance.get_first_seen(),
        })

    # Sorting data by version using LooseVersion
    data = sorted(data, key=lambda obj: LooseVersion(obj["version"].split(" ")[0]))

    wrapper_json = {
        "instances": data,
        "dll": model_to_dict(dll)
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


def get_dll_instance_by_sha256(request):
    # Retrieve SHA256 from GET parameters
    sha256 = request.GET.get('sha256', None)

    # Check if SHA256 is provided
    if not sha256:
        return JsonResponse({"error": "SHA256 parameter is required."}, status=400)

    try:
        # Query the DLLInstance model for the provided SHA256
        dll_instance = DLLInstance.objects.get(sha256__iexact=sha256)

        # Serialize the DLLInstance object
        data = serializers.serialize('json', [dll_instance, ])
        data = json.loads(data)

        # Extract the fields and add custom handling for related objects if necessary
        dll_instance_data = data[0]['fields']
        dll_instance_data["id"] = data[0]["pk"]
        # Example of adding related model data, customize according to your model relations
        dll_instance_data['windows_updates'] = list(
            dll_instance.windows_updates.values('name', 'release_date', 'release_version'))

        # Return the serialized DLLInstance
        return JsonResponse(dll_instance_data, safe=False)
    except DLLInstance.DoesNotExist:
        # Handle the case where no DLLInstance is found for the provided SHA256
        return JsonResponse({"error": "DLLInstance not found."}, status=404)


@require_http_methods(["GET"])
def get_dll_function_diffs(request, dll_name):
    # Step 1: Retrieve the DLL name from GET parameters
    # Step 2: Fetch related DLL instances sorted by 'version'
    try:
        dll = DLL.objects.get(name=dll_name)
    except DLL.DoesNotExist:
        return JsonResponse({'error': 'DLL not found'}, status=404)

    dll_instances = dll.dllinstance_set.all().order_by('version')
    # Placeholder for custom sorting function - to be implemented by you
    # dll_instances = custom_sort(dll_instances)

    # Step 3: Determine the number of recent DLL instances to compare
    n = request.GET.get('n', default=len(dll_instances))
    try:
        n = int(n)
    except ValueError:
        return JsonResponse({'error': 'Invalid number specified'}, status=400)

    diffs = []
    # Iterate over the n most recent DLL instances to find added functions
    for i in range(max(1, len(dll_instances) - n + 1), len(dll_instances)):
        current_instance = dll_instances[i]
        previous_instance = dll_instances[i - 1] if i - 1 >= 0 else None

        current_functions_set = set(current_instance.function_set.values_list('function_name', flat=True))
        if previous_instance:
            previous_functions_set = set(previous_instance.function_set.values_list('function_name', flat=True))
        else:
            previous_functions_set = set()

        added_functions = current_functions_set - previous_functions_set
        diffs.append({
            'dll_instance_sha256': current_instance.sha256,
            'version': current_instance.version,
            'added_functions': list(added_functions)
        })

    return JsonResponse({'dll_name': dll_name, 'function_diffs': diffs}, safe=False,
                        json_dumps_params={'indent': 2}) @ require_http_methods(["GET"])


def get_dll_function_diffs(request, dll_name):
    """
    This function shows recent changes to DLLs by returning newly added functions.

    We cannot diff between insider and non-insider as the DLL versions do not sort correctly.

    To solve this, we check to see if there are enough insider DLLs to provide a decent update.

    If there is not at least 3 insider preview DLLs, we ignore them and just diff the normal DLLs.
    """
    try:
        dll = DLL.objects.get(name=dll_name)
    except DLL.DoesNotExist:
        return JsonResponse({'error': 'DLL not found'}, status=404)

    # Do we have enough insiders?
    all_dll_instances = DLLInstance.objects.filter(dll__name=dll_name)
    insider_instances = [instance for instance in all_dll_instances if instance.is_insider()]

    if len(insider_instances) < 4:
        # Not enough insider DLL instances, lets default back
        dll_instances = [instance for instance in all_dll_instances if not instance.is_insider()]
    else:
        dll_instances = insider_instances

    dll_instances = sorted(dll_instances, key=lambda obj: LooseVersion(obj.version.split(" ")[0]))

    n = request.GET.get('n', default=4)
    try:
        n = int(n)
    except ValueError:
        return JsonResponse({'error': 'Invalid number specified'}, status=400)

    before_functions = set(
        dll_instances[len(dll_instances) - n - 1].function_set.values_list('function_name', flat=True)
    )

    after_functions = set(
        dll_instances[-1].function_set.values_list('function_name', flat=True)
    )

    added_functions = after_functions - before_functions
    removed_functions = before_functions - after_functions

    excluded_prefixes = ("FUN_", "wil_", "_")

    added_functions = set(f for f in added_functions if not f.startswith(excluded_prefixes))
    removed_functions = set(f for f in removed_functions if not f.startswith(excluded_prefixes))

    diffs = {
        'added_functions': list(added_functions),
        'removed_functions': list(removed_functions)
    }

    return JsonResponse({'dll_name': dll_name, 'function_diffs': diffs}, safe=False, json_dumps_params={'indent': 2})
