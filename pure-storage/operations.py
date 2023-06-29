""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
from connectors.core.connector import get_logger, ConnectorError
from .constants import *
from .pure_storage_api_auth import PureStorageAuth
logger = get_logger("pure-storage")


def get_alerts(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "continuation_token": params.get("continuation_token"),
        "ids": [string.strip() for string in params.get("ids").split(',')] if params.get("ids") else None,
        "names": [string.strip() for string in params.get("names").split(',')] if params.get("names") else None,
        "sort": [string.strip() for string in params.get("sort").split(',')] if params.get("sort") else None,
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
        "ids": [string.strip() for string in params.get("ids").split(',')] if params.get("ids") else None,
        "names": [string.strip() for string in params.get("names").split(',')] if params.get("names") else None,
        "sort": [string.strip() for string in params.get("sort").split(',')] if params.get("sort") else None,
        "fqdns": [string.strip() for string in params.get("fqdns").split(',')] if params.get("fqdns") else None,
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
        "resource_ids": [string.strip() for string in params.get("resource_ids").split(',')] if params.get("resource_ids") else None,
        "resource_names": [string.strip() for string in params.get("resource_names").split(',')] if params.get("resource_names") else None,
        "sort": [string.strip() for string in params.get("sort").split(',')] if params.get("sort") else None,
        "resource_fqdns": [string.strip() for string in params.get("resource_fqdns").split(',')] if params.get("resource_fqdns") else None,
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
        "resource_ids": [string.strip() for string in params.get("resource_ids").split(',')] if params.get("resource_ids") else None,
        "resource_names": [string.strip() for string in params.get("resource_names").split(',')] if params.get("resource_names") else None,
        "keys": [string.strip() for string in params.get("keys").split(',')] if params.get("keys") else None,
        "namespaces": [string.strip() for string in params.get("namespaces").split(',')] if params.get("namespaces") else None,
        "filter": params.get("filter"),
        "offset": params.get("offset"),
        "limit": params.get("limit")
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=ARRAYS_ENDPOINT+ '/tags', params=payload)
    return response


def delete_array_tags(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "resource_ids": [string.strip() for string in params.get("resource_ids").split(',')] if params.get("resource_ids") else None,
        "resource_names": [string.strip() for string in params.get("resource_names").split(',')] if params.get("resource_names") else None,
        "keys": [string.strip() for string in params.get("keys").split(',')] if params.get("keys") else None,
        "namespaces": [string.strip() for string in params.get("namespaces").split(',')] if params.get("namespaces") else None,
    }
    payload = build_payload(payload)
    response = ps.make_request(method='DELETE', endpoint=ARRAYS_ENDPOINT + '/tags', params=payload)
    return response


def create_or_update_array_tags(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "resource_ids": [string.strip() for string in params.get("resource_ids").split(',')] if params.get("resource_ids") else None,
        "resource_names": [string.strip() for string in params.get("resource_names").split(',')] if params.get("resource_names") else None,
        "namespaces": [string.strip() for string in params.get("namespaces").split(',')] if params.get("namespaces") else None,
        "tags": params.get('tags', [])
    }
    payload = build_payload(payload)
    response = ps.make_request(endpoint=ARRAYS_ENDPOINT + '/tags/batch', params=payload)
    return response


def get_controllers(config: dict, params: dict) -> dict:
    ps = PureStorageAuth(config=config)
    payload = {
        "continuation_token": params.get("continuation_token"),
        "ids": [string.strip() for string in params.get("ids").split(',')] if params.get("ids") else None,
        "names": [string.strip() for string in params.get("names").split(',')] if params.get("names") else None,
        "sort": [string.strip() for string in params.get("sort").split(',')] if params.get("sort") else None,
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
        "ids": [string.strip() for string in params.get("ids").split(',')] if params.get("ids") else None,
        "names": [string.strip() for string in params.get("names").split(',')] if params.get("names") else None,
        "file_system_ids": [string.strip() for string in params.get("file_system_ids").split(',')] if params.get("file_system_ids") else None,
        "file_system_names": [string.strip() for string in params.get("file_system_names").split(',')] if params.get("file_system_names") else None,
        "sort": [string.strip() for string in params.get("sort").split(',')] if params.get("sort") else None,
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
        "ids": [string.strip() for string in params.get("ids").split(',')] if params.get("ids") else None,
        "names": [string.strip() for string in params.get("names").split(',')] if params.get("names") else None,
        "sort": [string.strip() for string in params.get("sort").split(',')] if params.get("sort") else None,
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
        if type(v) is bool or v:
            built_payload[k] = v
        elif type(v) is dict:
            built_payload[k] = build_payload(v)
    return built_payload


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
