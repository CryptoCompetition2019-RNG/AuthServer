from .method import get_json_ret, json_response_zh


class AuthMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request, *args, **kwargs):
        if "application/json" in request.headers.get("Content-Type"):
            import json
            request.json = json.loads(request.body)
        else:
            request.json = request.POST

        if not request.path.startswith('/negotiate_key'):
            shared_secret = request.session.get("shared_secret")
            if shared_secret is None:
                return json_response_zh(get_json_ret(42, msg="请先协商密钥"))
            from Crypto.Util.number import long_to_bytes
            request.DH_key = long_to_bytes(shared_secret)[:16].ljust(16, b'\x00')

        if not request.path.startswith('/negotiate_key') and not request.path == '/dynamicauth_api3/':
            request.data = request.json.get("data")
            if request.data is None:
                return json_response_zh(get_json_ret(40, msg="请传递 data 参数"))

        user_name = request.session.get("user_name")
        if user_name:
            from UserModel.models import UserModel
            request.user = UserModel.objects.get(user_name=user_name)
            if request.user is None:
                request.session["user_name"] = None

        response = self.get_response(request)
        return response
