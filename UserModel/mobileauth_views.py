from AuthServer.method import json_response_zh


def mobileauth_api1(request):
    return json_response_zh({'msg': 'mobileauth_api1'})


def mobileauth_api2(request):
    return json_response_zh({'msg': 'mobileauth_api2'})
