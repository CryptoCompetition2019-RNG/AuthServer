from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from Crypto.Util.number import long_to_bytes

from AuthServer.method import json_response_zh, get_json_ret, decrypt_ecb
from .models import UserModel


@csrf_exempt
@require_POST
def register_api(request):
    """
    实现注册功能的 API
    :param request: 有效的请求应该包含一个形如以下实例的 post 数据：
        {"data": sm4( id.ljust(64, '\x00') + salt.ljust(64, '\x00') + A_pwd + B_pwd + sm3(IMEI) )}
    :return: 如果失败，则会返回相对应的错误码；如果成功返回 0
    """
    data = long_to_bytes(int(request.data, 16))
    plain = decrypt_ecb(request.DH_key, data).decode()
    if len(plain) != 64 * 5:
        return json_response_zh(get_json_ret(41))

    if UserModel.objects.filter(user_name=plain[:64]).exists():
        from AuthServer.settings import DEBUG
        if DEBUG:
            user = UserModel.objects.get(user_name=plain[:64])
            user.salt = plain[64:64*2]
            user.A_pwd = plain[64*2:64*3]
            user.B_pwd = plain[64*3:64*4]
            user.save()
        return json_response_zh(get_json_ret(0 if DEBUG else 52))
    UserModel.objects.create(
        user_name=plain[:64],
        salt=plain[64:64 * 2],
        A_pwd=plain[64 * 2:64 * 3],
        B_pwd=plain[64 * 3:64 * 4],
        hash_IMEI=plain[64 * 4:64 * 5]
    )
    return json_response_zh(get_json_ret(0))
