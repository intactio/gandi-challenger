Gandi DNS Challenger for certbot
================================

### Dependencies
* [keyring](https://pypi.org/project/keyring/)
* [requests](https://pypi.org/project/requests/)

### Setup (macOS Keychain)
```sh
security add-generic-password -a gandi-api-key -s gandi-api-key -w ${GANDI_API_KEY}
```

### How to use
```sh
certbot certonly --manual \
    -d "*.example.com" \
    -m hoge@example.com \
    --agree-tos \
    --manual-public-ip-logging-ok \
    --manual-auth-hook "${REPO_PATH}/gandi-challenger/gandi.py" \
    --manual-cleanup-hook "${REPO_PATH}/gandi-challenger/gandi.py --cleanup" \
    --preferred-challenges dns-01 \
    --server https://acme-v02.api.letsencrypt.org/directory
```
