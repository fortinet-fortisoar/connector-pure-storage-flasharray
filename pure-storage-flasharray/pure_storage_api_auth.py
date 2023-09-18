""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from datetime import datetime, timedelta
from time import time, ctime
from integrations.crudhub import make_request
import jwt
import requests
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config
from .constants import *

logger = get_logger('pure-storage-flasharray')


class PureStorageAuth:
    def __init__(self, config):
        self.verify_ssl = config.get('verify_ssl')
        self.server_url = config.get("server_url").strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://{0}'.format(self.server_url)
        self.api_version = config.get("api_version") if config.get("api_version") else API_VERSION
        self.access_token = self.get_validated_token(config) if config.get('access_token') else None

    def convert_ts_epoch(self, ts):
        try:
            datetime_object = datetime.strptime(ctime(ts), '%a %b %d %H:%M:%S %Y')
        except:
            datetime_object = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')

        return datetime_object.timestamp()

    def generate_access_token(self, config):
        try:
            payload = {
                'grant_type': GRANT_TYPE,
                'subject_token_type': SUBJECT_TOKEN_TYPE,
                'subject_token': generate_jwt_token(config)
            }
            resp = self.make_request_rest_api_call(method='POST', endpoint=AUTHORIZATION_ENDPOINT, data=payload, generate_token=True)
            logger.debug("Access token generated successfully !!!!!")
            ts_now = time()
            resp['expires_in'] = (ts_now + resp['expires_in']) if resp.get("expires_in") else None
            return resp
        except Exception as err:
            logger.error("{0}".format(err))
            raise ConnectorError("{0}".format(err))

    def get_validated_token(self, connector_config):
        connector_info = connector_config.get('connector_info')
        ts_now = time()
        if not connector_config.get('access_token'):
            logger.error('Error occurred while connecting server: Unauthorized')
            raise ConnectorError('Error occurred while connecting server: Unauthorized')
        expires = connector_config['expires_in']
        expires_ts = self.convert_ts_epoch(expires)
        if ts_now > float(expires_ts):
            logger.debug("Token expired at {0}".format(expires))
            token_resp = self.generate_access_token(connector_config)
            connector_config['access_token'] = token_resp['access_token']
            connector_config['expires_in'] = token_resp['expires_in']
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                     connector_config,
                                     connector_config['config_id'])
            return "Bearer {0}".format(connector_config.get('access_token'))
        else:
            logger.debug("Token is valid till {0}".format(expires))
            return "Bearer {0}".format(connector_config.get('access_token'))

    def make_request_rest_api_call(self, endpoint='', params=None, data=None, method='GET', headers=None, url=None, json_data=None, generate_token=False):
        try:
            if url is None:
                url = self.server_url + endpoint.format(self.api_version)
            if not generate_token:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": self.access_token
                }
            response = requests.request(method=method, url=url, headers=headers, data=data, json=json_data,
                                        params=params, verify=self.verify_ssl, timeout=MAX_REQUEST_TIMEOUT)
            if response.ok:
                return response.json()
            else:
                try:
                    logger.error("Error: {0}".format(response.json()))
                    raise ConnectorError('Error: {0}'.format(response.json()))
                except Exception as error:
                    raise ConnectorError('{0}'.format(response.text if response.text else str(response)))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def _check_health(config):
    try:
        ps_auth = PureStorageAuth(config)
        connector_info = config.get('connector_info')
        if 'access_token' not in config:
            token_resp = ps_auth.generate_access_token(config)
            config['access_token'] = token_resp.get('access_token')
            config['expires_in'] = token_resp.get('expires_in')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id'])
            return True
        else:
            token_resp = ps_auth.get_validated_token(config)
            return True
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def generate_jwt_token(config):
    if isinstance(config.get('private_key', {}), dict) and config.get('private_key', {}).get('@type') == "File":
        url = config.get('private_key', {}).get('@id')
        private_key = make_request(url, 'GET')
    else:
        logger.warning("Type of private key is not file")
        private_key = config.get('private_key')
    payload = {
        "aud": config.get('aud'),
        "sub": config.get('sub'),
        "iss": config.get('iss'),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=15)
    }
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": config.get('kid')
    }
    token = jwt.encode(payload, private_key, algorithm='RS256', headers=header)
    logger.debug("JWT token successfully generated...")
    return token
