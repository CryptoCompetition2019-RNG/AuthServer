from django.http import JsonResponse


def json_response_zh(json_data):
    """
    因为返回含中文的 Json 数据总是需要设置 {'ensure_ascii': False}，所以直接在此集成
    :param json_data: 需要返回的数据
    """
    return JsonResponse(json_data, json_dumps_params={'ensure_ascii': False})


def get_json_ret(code, msg=None, err=None, data=None):
    """
    :param code: 一个整数型的标识码
    :return: 一个字典对象，包含 code 键值和 msg 信息或 err 信息。
    """
    res = {
        0: {"code": 0, "msg": "请求正常"},
        # TODO: 以 4 开头标识用户请求错误
        40: {"code": 40, "msg": "请求错误", "err": "请求参数缺失"},
        41: {"code": 41, "msg": "请求错误", "err": "请求参数错误"},
        42: {"code": 42, "msg": "请求错误", "err": "请求逻辑错误"},
        # TODO: 以 5 开头标识服务器检查错误
        # TODO: 以 6 开头表示第三方错误
    }[code]
    if err is not None: res["err"] = err
    if msg is not None: res["msg"] = msg
    if data is not None: res["data"] = data
    return res
