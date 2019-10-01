from AuthServer.method import json_response_zh


def pcauth_api1(request):
    return json_response_zh({"msg": "pcauth_api1"})


def pcauth_api2(request):
    return json_response_zh({"msg": "pcauth_api2"})