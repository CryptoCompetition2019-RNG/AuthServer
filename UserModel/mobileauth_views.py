from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from AuthServer.method import json_response_zh, get_json_ret, encrypt_ecb, decrypt_ecb
from Crypto.Util.number import getRandomNBitInteger, long_to_bytes, bytes_to_long

from .models import UserModel


@csrf_exempt
@require_POST
def mobileauth_api1(request):
    """
    移动端进行验证的第一步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') )}
    :return: 如果一切验证成功，则正常应该返回下面的内容：
        {"data": sm4_{salt}( r2 + A_pwd )}
    """
    data = long_to_bytes(int(request.data, 16))
    if len(data) != 64:
        return json_response_zh(get_json_ret(41))

    print(decrypt_ecb(request.DH_key, data), data, request.DH_key)
    user_name = decrypt_ecb(request.DH_key, data).decode()
    user = UserModel.objects.filter(user_name=user_name).first()
    if user is None:
        return json_response_zh(get_json_ret(41))
    request.session['user_name'] = user_name

    user.random_value2 = hex(getRandomNBitInteger(256))[2:].ljust(64, '\x00')
    user.save()
    ret_data = encrypt_ecb(user.get_salt_sm4_key(), (user.random_value2 + user.A_pwd).encode())
    return json_response_zh(get_json_ret(0, data=ret_data.hex()))


@csrf_exempt
@require_POST
def mobileauth_api2(request):
    """
    移动端验证口令的第二步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据
        {"data": sm4_{DH_key}( hex(r2) + B_pwd* )}
    :return: B_pwd* 与 B_pwd 是否相等
    """
    data = long_to_bytes(int(request.data, 16))
    if len(data) != 64 * 2:
        return json_response_zh(get_json_ret(41))

    plain = decrypt_ecb(request.DH_key, data).decode()
    if plain[:64] != request.user.random_value2:
        return json_response_zh(get_json_ret(50, msg="随机数错误"))
    request.user.random_value2 = None
    request.user.save()
    return json_response_zh(get_json_ret(0 if plain[64:] == request.user.B_pwd else 50))
