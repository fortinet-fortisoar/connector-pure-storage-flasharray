""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .constants import *
from .pure_storage_api_auth import PureStorageAuth


def get_alerts(config: dict, params: dict) -> dict:
    return retrieve_resources(config, params, ALERTS_ENDPOINT)


def get_arrays(config: dict, params: dict) -> dict:
    return retrieve_resources(config, params, ARRAYS_ENDPOINT)


def get_controllers(config: dict, params: dict) -> dict:
    return retrieve_resources(config, params, CONTROLLER_ENDPOINT)


def get_directories(config: dict, params: dict) -> dict:
    return retrieve_resources(config, params, DIRECTORY_ENDPOINT)


def get_drives(config: dict, params: dict) -> dict:
    return retrieve_resources(config, params, DRIVE_ENDPOINT)


def get_audits(config: dict, params: dict) -> dict:
    return retrieve_resources(config, params, AUDIT_ENDPOINT)


def get_volumes(config: dict, params: dict) -> dict:
    return retrieve_resources(config, params, VOLUME_ENDPOINT)


def get_protection_groups(config: dict, params: dict) -> dict:
    return retrieve_resources(config, params, PROTECTION_GROUP_ENDPOINT)


def get_sessions(config: dict, params: dict) -> dict:
    return retrieve_resources(config, params, SESSION_ENDPOINT)


def build_payload(params):
    built_payload = {}
    for k, v in params.items():
        if k in ['ids', 'names', 'sort', "fqdns", "file_system_ids", "file_system_names"]:
            v = convert_string_to_list(v)
        if type(v) is dict:
            built_payload[k] = build_payload(v)
        elif isinstance(v, (int, bool, float)) or v:
            built_payload[k] = v
    return built_payload


def convert_string_to_list(input_string):
    if isinstance(input_string, (list, tuple)):
        return ",".join(map(str, input_string))
    return input_string


def retrieve_resources(config, params, endpoint):
    ps = PureStorageAuth(config)
    payload = build_payload(params)
    response = ps.make_request_rest_api_call(endpoint=endpoint, params=payload)
    return response


operations = {
    "get_alerts": get_alerts,
    "get_arrays": get_arrays,
    "get_controllers": get_controllers,
    "get_directories": get_directories,
    "get_drives": get_drives,
    'get_audits': get_audits,
    'get_volumes': get_volumes,
    'get_protection_groups': get_protection_groups,
    'get_sessions': get_sessions
}
