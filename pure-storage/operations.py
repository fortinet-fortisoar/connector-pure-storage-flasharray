""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger
from .constants import *
from .pure_storage_api_auth import PureStorageAuth
logger = get_logger("pure-storage")


def get_alerts(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "continuation_token": params.get("continuation_token"),
        "ids": convert_string_to_list(params.get("ids")),
        "names": convert_string_to_list(params.get("names")),
        "sort": convert_string_to_list(params.get("sort")),
        "filter": params.get("filter"),
        "offset": params.get("offset"),
        "limit": params.get("limit")
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=ALERTS_ENDPOINT, params=payload)
    return response


def get_arrays(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "continuation_token": params.get("continuation_token"),
        "ids": convert_string_to_list(params.get("ids")),
        "names": convert_string_to_list(params.get("names")),
        "sort": convert_string_to_list(params.get("sort")),
        "fqdns": convert_string_to_list(params.get("fqdns")),
        "filter": params.get("filter"),
        "offset": params.get("offset"),
        "limit": params.get("limit")
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=ARRAYS_ENDPOINT, params=payload)
    return response


def get_array_support_contracts(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "continuation_token": params.get("continuation_token"),
        "resource_ids": convert_string_to_list(params.get("resource_ids")),
        "resource_names": convert_string_to_list(params.get("resource_names")),
        "sort": convert_string_to_list(params.get("sort")),
        "resource_fqdns": convert_string_to_list(params.get("resource_fqdns")),
        "filter": params.get("filter"),
        "offset": params.get("offset"),
        "limit": params.get("limit")
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=ARRAYS_ENDPOINT + '/support-contracts', params=payload)
    return response


def get_array_tags(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "continuation_token": params.get("continuation_token"),
        "resource_ids": convert_string_to_list(params.get("resource_ids")),
        "resource_names": convert_string_to_list(params.get("resource_names")),
        "keys": convert_string_to_list(params.get("keys")),
        "namespaces": convert_string_to_list(params.get("namespaces")),
        "filter": params.get("filter"),
        "offset": params.get("offset"),
        "limit": params.get("limit")
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=ARRAYS_ENDPOINT + '/tags', params=payload)
    return response


def delete_array_tags(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "resource_ids": convert_string_to_list(params.get("resource_ids")),
        "resource_names": convert_string_to_list(params.get("resource_names")),
        "keys": convert_string_to_list(params.get("keys")),
        "namespaces": convert_string_to_list(params.get("namespaces")),
    }
    payload = build_payload(payload)
    response = ps.make_request(method='DELETE', endpoint=ARRAYS_ENDPOINT + '/tags', params=payload)
    return response


def create_or_update_array_tags(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "resource_ids": convert_string_to_list(params.get("resource_ids")),
        "resource_names": convert_string_to_list(params.get("resource_names")),
        "namespaces": convert_string_to_list(params.get("namespaces")),
        "tags": params.get('tags', [])
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=ARRAYS_ENDPOINT + '/tags/batch', params=payload)
    return response


def get_controllers(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "continuation_token": params.get("continuation_token"),
        "ids": convert_string_to_list(params.get("ids")),
        "names": convert_string_to_list(params.get("names")),
        "sort": convert_string_to_list(params.get("sort")),
        "filter": params.get("filter"),
        "offset": params.get("offset"),
        "limit": params.get("limit")
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=CONTROLLER_ENDPOINT, params=payload)
    return response


def get_directories(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "continuation_token": params.get("continuation_token"),
        "ids": convert_string_to_list(params.get("ids")),
        "names": convert_string_to_list(params.get("names")),
        "file_system_ids": convert_string_to_list(params.get("file_system_ids")),
        "file_system_names": convert_string_to_list(params.get("file_system_names")),
        "sort": convert_string_to_list(params.get("sort")),
        "filter": params.get("filter"),
        "offset": params.get("offset"),
        "limit": params.get("limit")
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=DIRECTORY_ENDPOINT, params=payload)
    return response


def get_drives(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "continuation_token": params.get("continuation_token"),
        "ids": convert_string_to_list(params.get("ids")),
        "names": convert_string_to_list(params.get("names")),
        "sort": convert_string_to_list(params.get("sort")),
        "filter": params.get("filter"),
        "offset": params.get("offset"),
        "limit": params.get("limit")
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=DRIVE_ENDPOINT, params=payload)
    return response


def build_payload(params):
    built_payload = {}
    for k, v in params.items():
        if type(v) is dict:
            built_payload[k] = build_payload(v)
        elif isinstance(v, (int, bool, float)) or v:
            built_payload[k] = v
    return built_payload


def convert_string_to_list(input_string):
    if input_string and type(input_string) is str:
        return [string.strip() for string in input_string.split(',')]
    elif isinstance(input_string, list):
        return input_string
    return None


operations = {
    "get_alerts": get_alerts,
    "get_arrays": get_arrays,
    "get_array_support_contracts": get_array_support_contracts,
    "get_array_tags": get_array_tags,
    "delete_array_tags": delete_array_tags,
    "create_or_update_array_tags": create_or_update_array_tags,
    "get_controllers": get_controllers,
    "get_directories": get_directories,
    "get_drives": get_drives
}
