from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from AuthServer.method import json_response_zh, get_json_ret, encrypt_ecb, decrypt_ecb
from Crypto.Util.number import long_to_bytes

from .models import UserModel


@csrf_exempt
@require_POST
def dynamicauth_api1(request):
    """
    动态二维码验证的第一步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') )}
    :return: {data: sm4_{salt}(r3)}
    """
    data = long_to_bytes(int(request.data, 16))
    if len(data) != 64:
        return json_response_zh(get_json_ret(41))

    user_name = decrypt_ecb(request.DH_key, data).decode()
    user = UserModel.objects.filter(user_name=user_name).first()
    if user is None:
        return json_response_zh(get_json_ret(41))
    request.session['user_name'] = user_name

    from Crypto.Util.number import getRandomNBitInteger
    user.random_value3 = hex(getRandomNBitInteger(256))[2:].ljust(64, '\x00')
    user.save()
    ret_data = encrypt_ecb(user.get_salt_sm4_key(), user.random_value3.encode())
    return json_response_zh(get_json_ret(0, data=ret_data.hex()))


@csrf_exempt
@require_POST
def dynamicauth_api2(request):
    """
    动态二维码验证的第二步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') + H(IMEI) + r3 )}
    :return: 如果所有检查成功，则会返回 0 表示登录成功，但是这个信号并不会传递到手机上
    """
    data = long_to_bytes(int(request.data, 16))
    if len(data) != 64 * 3:
        return json_response_zh(get_json_ret(41))

    plain = decrypt_ecb(request.DH_key, data).decode()
    user_name = plain[:64]
    user = UserModel.objects.filter(user_name=user_name).first()
    if user is None:
        return json_response_zh(get_json_ret(41))
    request.session['user_name'] = user_name

    if user.hash_IMEI != plain[64: 64 * 2]:
        return json_response_zh(get_json_ret(50, msg="手机 IMEI 码验证失败"))
    if user.random_value3 != plain[64 * 2: 64 * 3]:
        return json_response_zh(get_json_ret(50, msg="随机数验证错误"))
    from AuthServer.settings import DEBUG
    if not DEBUG:
        user.random_value3 = None
    user.login_status = True
    user.save()
    return json_response_zh(get_json_ret(0, msg='登录成功'))

@csrf_exempt
@require_POST
def dynamicauth_api3(request):
    """
    动态二维码验证的第三步，PC 端检查自己是否登录成功
    """
    return json_response_zh(get_json_ret(0 if request.user.login_status else 51))
