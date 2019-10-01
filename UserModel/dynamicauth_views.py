from AuthServer.method import json_response_zh


def dynamicauth_api1(request):
    return json_response_zh({'msg': 'dynamicauth_api1'})


def dynamicauth_api2(request):
    return json_response_zh({'msg': 'dynamicauth_Api2'})
