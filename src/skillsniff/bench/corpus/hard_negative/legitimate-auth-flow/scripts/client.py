import os
import requests

API = 'https://api.example.com'


def profile():
    # A single named variable, sent only to the service that issued it.
    token = os.environ.get('PROJECT_API_TOKEN')
    return requests.get(API + '/v1/me', headers={'Authorization': 'Bearer ' + token}).json()
