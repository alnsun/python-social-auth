#coding:utf8
# author: alnsun.cn@gmail.com  https://bitbucket.org/alnsun
# https://github.com/alnsun

"""
Weibo OAuth2 backend
"""
from social.backends.oauth import BaseOAuth2
from requests import request, ConnectionError
import urllib


class TWeiboOAuth2(BaseOAuth2):
    """Weibo (of Tencent) OAuth authentication backend"""
    name = 'tweibo'
    ID_KEY = 'openid'
    AUTHORIZATION_URL = 'https://open.t.qq.com/cgi-bin/oauth2/authorize'
    REFRESH_TOKEN_URL = 'https://open.t.qq.com/cgi-bin/oauth2/access_token'
    ACCESS_TOKEN_URL = 'https://open.t.qq.com/cgi-bin/oauth2/access_token'
    ACCESS_TOKEN_METHOD = 'POST'
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ('openid', 'id'),
        ('name', 'username'),
        ('head', 'profile_image_url'),
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

        def _decode(text):
            ret = {}
            for item in text.split('&'):
                k, v = map(urllib.unquote, item.split('=')) #item.split('=')
                ret[k] = v
            return ret

        if not kwargs.has_key('params'):
            return _decode(resp.text)

        data = resp.json()
        return data

    def get_user_details(self, response):
        """Return user details from Weibo of Tencent. API URL is:
        http://open.t.qq.com/api/user/info?format=json&oauth_consumer_key=APP_KEY&
               access_token=ACCESSTOKEN&openid=OPENID&clientip=CLIENTIP&oauth_version=2.a&
               scope=all
        ref: http://wiki.open.t.qq.com/index.php/OAuth2.0%E9%89%B4%E6%9D%83
        """
        username = response.get('name', '')

        fullname, first_name, last_name = self.get_user_names(
            fullname=response.get('nick', '')
        )

        return {'username': username,
                'email': response.get('email', ''),
                'fullname': fullname,
                'first_name': first_name,
                'last_name': last_name}

    def extra_data(self, user, uid, response, details):
        """Return deafault extra data to store in extra_data field"""
        data = {}
        for entry in (self.EXTRA_DATA or []) + self.setting('EXTRA_DATA', []):
            if not isinstance(entry, (list, tuple)):
                entry = (entry,)
            size = len(entry)
            if size >= 1 and size <= 3:
                if size == 3:
                    name, alias, discard = entry
                elif size == 2:
                    (name, alias), discard = entry, False
                elif size == 1:
                    name = alias = entry[0]
                    discard = False
                value = response.get(name, '') or details.get(name)
                if not value:
                    value = response.get('data').get(name)
                if discard and not value:
                    continue
                data[alias] = value
        return data

    def user_data(self, access_token, *args, **kwargs):
        client_id = self.get_key_and_secret()[0]
        return self.get_json('https://open.t.qq.com/api/user/info',
                              params = {
                'format':'json',
                'access_token': access_token,
                'oauth_consumer_key': client_id,
                'openid': kwargs['response']['openid'],
                'oauth_version': '2.a',
                'scope': 'all'
                           })
