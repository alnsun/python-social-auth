#coding:utf8
# author:alnsun.cn@gmail.com  https://bitbucket.org/alnsun
# https://github.com/alnsun

"""
Weixin OAuth2 backend
"""
from social.backends.oauth import BaseOAuth2
from social.p3 import urlencode, unquote
from requests import request, ConnectionError
from urllib import quote_plus
import urllib

class WeixinOAuth2(BaseOAuth2):
    """Weixin (of Tencent) OAuth authentication backend"""
    name = 'weixin'
    ID_KEY = 'openid'
    AUTHORIZATION_URL = 'https://open.weixin.qq.com/connect/oauth2/authorize'
    REFRESH_TOKEN_URL = 'https://api.weixin.qq.com/sns/oauth2/refresh_token'
    ACCESS_TOKEN_URL = 'https://api.weixin.qq.com/sns/oauth2/access_token'
    ACCESS_TOKEN_METHOD = 'POST'
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ('openid', 'id'),
        ('nickname', 'username'),
        ('headimgurl', 'profile_image_url'),
        ('sex', 'gender')
    ]

    def request(self, url, method='GET', *args, **kwargs):
        kwargs.setdefault('timeout', self.setting('REQUESTS_TIMEOUT') or
                                     self.setting('URLOPEN_TIMEOUT'))
        try:
            response = request(method, url, *args, **kwargs)
        except ConnectionError as err:
            raise AuthFailed(self, str(err))
        response.raise_for_status()
        return response

    def get_json(self, url, *args, **kwargs):
        resp = self.request(url, *args, **kwargs)

        data = resp.json()
        return data

    def get_user_details(self, response):
        """Return user details from Weixin of Tencent.
        """
        username = response.get('openid', '')
        nickname = response.get('nickname', '')
        nickname = nickname.encode('unicode_escape').decode('string_escape').decode('utf-8')

        fullname, first_name, last_name = self.get_user_names(
            fullname=nickname
        )

        return {'username': username,
                'email': response.get('email', ''),
                'fullname': fullname,
                'first_name': first_name,
                'last_name': last_name}

    def user_data(self, access_token, *args, **kwargs):
        client_id = self.get_key_and_secret()[0]
        return self.get_json('https://api.weixin.qq.com/sns/userinfo',
                              params = {
                'access_token': access_token,
                'openid': kwargs['response']['openid'],
                'lang': 'zh_CN'
                              })

    def get_redirect_uri(self, state=None):
        """Build redirect with redirect_state parameter."""
        uri = self.redirect_uri
        if self.REDIRECT_STATE and state:
            uri = url_add_parameters(uri, {'redirect_state': state})
        return uri

    def auth_params(self, state=None):
        client_id, client_secret = self.get_key_and_secret()
        params = (
            ('appid', client_id),
            ('redirect_uri', self.get_redirect_uri(state)),
            ('scope', 'snsapi_userinfo'),
        )
        if self.STATE_PARAMETER and state:
            params = params + (('state', state),)
        if self.RESPONSE_TYPE:
            params = params + (('response_type', self.RESPONSE_TYPE),)
        return params

    def auth_url(self):
        """Return redirect url"""
        if self.STATE_PARAMETER or self.REDIRECT_STATE:
            # Store state in session for further request validation. The state
            # value is passed as state parameter (as specified in OAuth2 spec),
            # but also added to redirect, that way we can still verify the
            # request if the provider doesn't implement the state parameter.
            # Reuse token if any.
            name = self.name + '_state'
            state = self.strategy.session_get(name)
            if state is None:
                state = self.state_token()
                self.strategy.session_set(name, state)
        else:
            state = None

        params = self.auth_params(state)
        params = urlencode(params)
        if not self.REDIRECT_STATE:
            # redirect_uri matching is strictly enforced, so match the
            # providers value exactly.
            params = unquote(params)
        url = self.AUTHORIZATION_URL + '?' + params
        url = url + '#wechat_redirect'
        print 'url=', url
        return url

    def auth_complete_params(self, state=None):
        client_id, client_secret = self.get_key_and_secret()
        return {
            'grant_type': 'authorization_code',  # request auth code
            'code': self.data.get('code', ''),  # server response code
            'client_id': client_id,
            'appid': client_id,
            'client_secret': client_secret,
            'secret': client_secret,
            'redirect_uri': self.get_redirect_uri(state)
        }

