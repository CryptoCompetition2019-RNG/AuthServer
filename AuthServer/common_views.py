from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_exempt
from Crypto.Util.number import getPrime, long_to_bytes

from .method import json_response_zh, get_json_ret


@csrf_exempt
@require_POST
def negotiate_key1(request):
    """
    实现 DH 密钥交换的 API 的第一步，会生成一个 1024 位的随机密钥
    :param request: POST 请求
    :return: 服务端选择 p 和 g 存储进入 session，并且 json 返回；
    """
    # TODO: to make p as constant
    # DH_p = getPrime(256)
    DH_g, DH_p = 5, 107034953391847476745000369688787439523773649371884781670688252695402488571357
    request.session['DH_g'] = DH_g
    request.session['DH_p'] = DH_p
    return json_response_zh(get_json_ret(0, data={
        "g": hex(DH_g)[2:], "p": hex(DH_p)[2:]
    }))


@csrf_exempt
@require_POST
def negotiate_key2(request):
    """
    实现 DH 密钥交换 API 的第二步，这一步会生成服务器端的秘密信息，计算会话密钥后存入 session
    :param request: data 内容被认为是十六进制的 g^speer % p
    :return: 返回的 data 中是十六进制的 g^sthis % p
    """
    try:
        data = int(request.json.get("data"), 16)
        DH_g, DH_p = request.session.get('DH_g'), request.session.get('DH_p')
        assert DH_p is not None and DH_g is not None
    except TypeError:
        return json_response_zh(get_json_ret(40))
    except ValueError:
        return json_response_zh(get_json_ret(41))
    except AssertionError:
        return json_response_zh(get_json_ret(42))

    secret = getPrime(64)
    request.session['shared_secret'] = pow(data, secret, DH_p)
    return json_response_zh(get_json_ret(0, data=hex(pow(DH_g, secret, DH_p))[2:]))


@csrf_exempt
@require_POST
def ask_salt(request):
    """
    在 DEBUG 状态下传入 username, 查询 salt 信息
    :param request: 明文传输的 64 个字节 username
    :return: 如果开启 debug 模式，则返回 hex(user_salt_key)
    """
    from .settings import DEBUG
    if not DEBUG:
        return json_response_zh(get_json_ret(53))
    if len(request.data) != 64:
        return json_response_zh(get_json_ret(41))
    from UserModel.models import UserModel
    user = UserModel.objects.filter(user_name=request.data).first()
    if user is None:
        return json_response_zh(get_json_ret(41))
    assert isinstance(user, UserModel)
    return json_response_zh(get_json_ret(0, data=user.get_salt_sm4_key().hex() ))