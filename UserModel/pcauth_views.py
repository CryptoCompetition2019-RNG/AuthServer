from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from AuthServer.method import json_response_zh, get_json_ret, decrypt_ecb, encrypt_ecb
from Crypto.Util.number import long_to_bytes

from .models import UserModel


@csrf_exempt
@require_POST
def pcauth_api1(request):
    """
    PC 端验证口令的第一步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') ) + sm4_{salt}( hex(r1) ) }
    """
    data = long_to_bytes(int(request.data, 16))
    if len(data) != 64 * 2:
        return json_response_zh(get_json_ret(41))

    user_name = decrypt_ecb(request.DH_key, data[:64]).decode()
    user = UserModel.objects.filter(user_name=user_name).first()
    if user is None:
        return json_response_zh(get_json_ret(41))
    user.random_value1 = decrypt_ecb(user.get_salt_sm4_key(), data[64:]).decode()
    user.save()
    return json_response_zh(get_json_ret(0))


@csrf_exempt
@require_POST
def pcauth_api2(request):
    """
    pc 端验证口令的第二步，PC 端不断请求服务器，查看第一步是否完成
    :param request: 一个正常的请求应该包含如下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') )}
    :return:
    """
    data = long_to_bytes(int(request.data, 16))
    if len(data) != 64:
        return json_response_zh(get_json_ret(41))

    user_name = decrypt_ecb(request.DH_key, data).decode()
    user = UserModel.objects.filter(user_name=user_name).first()
    if user is None:
        return json_response_zh(get_json_ret(41))
    if user.random_value1 is None:
        return json_response_zh(get_json_ret(42))
    request.session['user_name'] = user_name

    ret_data = encrypt_ecb(request.DH_key, (user.random_value1 + user.A_pwd).encode())
    return json_response_zh(get_json_ret(0, data=ret_data.hex()))


@csrf_exempt
@require_POST
def pcauth_api3(request):
    """
    PC 端验证口令的第三步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据
        {"data": sm4_{DH_key}( hex(r1) + B_pwd* )}
    :return: B_pwd* 与 B_pwd 是否相等
    """
    data = long_to_bytes(int(request.data, 16))
    if len(data) != 64 * 2:
        return json_response_zh(get_json_ret(41))

    plain = decrypt_ecb(request.DH_key, data).decode()
    if plain[:64] != request.user.random_value1:
        return json_response_zh(get_json_ret(50, msg="随机数错误"))
    request.user.random_value1 = None
    request.user.save()
    return json_response_zh(get_json_ret(0 if plain[64:] == request.user.B_pwd else 50))
