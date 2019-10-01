from AuthServer.method import json_response_zh


def register_api(request):
    return json_response_zh({"msg": "测试"})
