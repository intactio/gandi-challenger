#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

from __future__ import print_function

import os
import requests
import keyring
import argparse


CERTBOT_VALIDATION = os.environ.get('CERTBOT_VALIDATION', None)
DOMAIN = os.environ.get('CERTBOT_DOMAIN', None)

GANDI_API_URI="https://dns.api.gandi.net/api/v5/zones"
GANDI_API_KEY=keyring.get_password('gandi-api-key', 'gandi-api-key')
AUTH_HEADERS={'X-Api-Key': GANDI_API_KEY}


class GandiChallenger(object):
    def __init__(self):
        self._target_zone = None
        self._target_acme_record = None

        self._init_target_zone(DOMAIN)
        self._init_target_acme_record()

    def _init_target_zone(self, target_domain):
        zones = requests.get(GANDI_API_URI, headers=AUTH_HEADERS).json()
        for zone in zones:
            if zone['name'] == target_domain:
                self._target_zone = zone

    def _init_target_acme_record(self):
        url = "%s/_acme-challenge" % (self._target_zone['zone_records_href'])
        acme_records = requests.get(url, headers=AUTH_HEADERS).json()
        for acme_record in acme_records:
            if acme_record['rrset_name'] == "_acme-challenge" and \
                    acme_record['rrset_type'] == "TXT":
                self._target_acme_record = acme_record

    def set_acme_challenge(self, validation):
        if self._target_acme_record:
            # update record
            method = "update"
            url = self._target_acme_record['rrset_href']
            payload = {"rrset_ttl": 300, "rrset_values": [validation]}
            result = requests.put(url, headers=AUTH_HEADERS, json=payload).json()
        else:
            # create record
            method = "create"
            url = self._target_zone['zone_records_href']
            payload = {"rrset_ttl": 300, "rrset_values": [validation],
                    "rrset_name": "_acme-challenge", "rrset_type": "TXT"}
            result = requests.post(url, headers=AUTH_HEADERS, json=payload).json()

        print("%s (%s): %s" % (result['message'], method, payload))

    def del_acme_challenge(self):
        if not self._target_acme_record:
            print("DNS Record is not exist")
            return

        url = self._target_acme_record['rrset_href']
        result = requests.delete(url, headers=AUTH_HEADERS)
        if result.status_code == 204:
            print("DNS Record Deleted")
        else:
            print(result.reason)


def main():
    parser = argparse.ArgumentParser(description='certbot challenger for gandi')
    parser.add_argument('--cleanup', action='store_true', help="cleanup acme record")
    args = parser.parse_args()

    gandi_challenger = GandiChallenger()
    if args.cleanup:
        gandi_challenger.del_acme_challenge()
    else:
        gandi_challenger.set_acme_challenge(CERTBOT_VALIDATION)


if __name__ == "__main__":
    main()
