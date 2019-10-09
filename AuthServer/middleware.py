from .method import get_json_ret, json_response_zh


class AuthMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request, *args, **kwargs):
        if not request.path.startswith('/negotiate_key'):
            request.DH_key = request.session.get("DH_key")
            if request.DH_key is None:
                return json_response_zh(get_json_ret(42, msg="请先协商密钥"))

            request.data = request.POST.get("data")
            if request.data is None:
                return json_response_zh(get_json_ret(40, msg="请传递 data 参数"))

        user_name = request.session["user_name"]
        if user_name:
            from UserModel.models import UserModel
            request.user = UserModel.objects.get(user_name=user_name)
            if request.user is None:
                request.session["user_name"] = None

        response = self.get_response(request)
        return response
