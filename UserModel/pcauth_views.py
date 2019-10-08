from django.views.decorators.http import require_POST
from AuthServer.method import json_response_zh, get_json_ret, decrypt_ecb, encrypt_ecb

from .models import UserModel


@require_POST
def pcauth_api1(request):
    """
    PC 端验证口令的第一步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') ) + sm4_{salt}( hex(r1) ) }
    """
    data = request.POST.get("data")
    if data is None:
        return json_response_zh(get_json_ret(40))
    if len(data) != 64 * 2:
        return json_response_zh(get_json_ret(41))

    DH_key = request.session['DH_key']
    if DH_key is None:
        return json_response_zh(get_json_ret(42))
    plain = decrypt_ecb(DH_key, data)

    user = UserModel.objects.get(user_name=plain[:64])
    if user is None:
        return json_response_zh(get_json_ret(41))
    user.random_value1 = plain[64:]
    user.save()
    return json_response_zh(get_json_ret(0))


@require_POST
def pcauth_api2(request):
    """
    pc 端验证口令的第二步，PC 端不断请求服务器，查看第一步是否完成
    :param request: 一个正常的请求应该包含如下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') )}
    :return:
    """
    data = request.POST.get("data")
    if data is None:
        return json_response_zh(get_json_ret(40))
    if len(data) != 64:
        return json_response_zh(get_json_ret(41))

    DH_key = request.session['DH_key']
    if DH_key is None:
        return json_response_zh(get_json_ret(42))
    user_name = decrypt_ecb(DH_key, data)

    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(41))
    if user.random_value1 is None:
        return json_response_zh(get_json_ret(42))
    request.session['user_name'] = user_name

    ret_data = encrypt_ecb(DH_key, user.random_value1+ user.A_pwd)
    return json_response_zh(get_json_ret(0, data=ret_data))


@require_POST
def pcauth_api3(request):
    """
    PC 端验证口令的第三步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据
        {"data": sm4_{DH_key}( hex(r1) + B_pwd* )}
    :return: B_pwd* 与 B_pwd 是否相等
    """
    data = request.POST.get("data")
    if data is None:
        return json_response_zh(get_json_ret(40))
    if len(data) != 64 * 2:
        return json_response_zh(get_json_ret(41))

    user_name = request.session['user_name']
    if user_name is None:
        return json_response_zh(get_json_ret(42))
    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(42))

    DH_key = request.session['DH_key']
    if DH_key is None:
        return json_response_zh(get_json_ret(42))
    plain = decrypt_ecb(DH_key, data)
    if plain[:64] != user.random_value1:
        return json_response_zh(get_json_ret(50, msg="随机数错误"))
    user.random_value1 = None
    user.save()
    return json_response_zh(get_json_ret(0 if plain[64:] == user.B_pwd else 50))
