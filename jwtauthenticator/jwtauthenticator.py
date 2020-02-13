from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode, Bool
import jwt


class JSONWebTokenLoginHandler(BaseHandler):

    async def get(self):

        # Read config
        access_param_name = self.authenticator.access_param_name
        refresh_param_name = self.authenticator.refresh_param_name
        signing_certificate = self.authenticator.signing_certificate
        secret = self.authenticator.secret
        username_claim_field = self.authenticator.username_claim_field
        audience = self.authenticator.expected_audience

        # Read values
        auth_cookie_content = self.get_cookie("XSRF-TOKEN", "")
        access_param = self.get_argument(self.authenticator.access_param_name, default=False)
        refresh_param = self.get_argument(self.authenticator.refresh_param_name, default=False)

        # Determine whether to use cookie content or query parameters
        if auth_cookie_content:
            access_token = auth_cookie_content
            refresh_token = "" # TODO: get both tokens from this
        elif access_param and refresh_param:
            access_token = access_param
            refresh_token = refresh_param
        else:
            raise web.HTTPError(401)

        # Parse access token
        claims = ""
        if secret:
            claims = self.verify_jwt_using_secret(access_token, secret, audience)
        elif signing_certificate:
            claims = self.verify_jwt_using_certificate(access_token, signing_certificate, audience)
        else:
           raise web.HTTPError(401)

        # JWT was valid
        self.log.info("Claims: %s", claims)
        username = self.retrieve_username(claims, username_claim_field)

        user = self.user_from_username(username)
        self.set_login_cookie(user)

        # Persist to database
        auth_info = {
            "name": username,
            "auth_state": {
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        }
        await self.auth_to_user(auth_info)

        _url = url_path_join(self.hub.server.base_url, 'spawn')
        next_url = self.get_argument('next', default=False)
        if next_url:
             _url = next_url

        self.redirect(_url)

    def verify_jwt_using_certificate(self, token, signing_certificate, audience):
        with open(signing_certificate, 'r') as rsa_public_key_file:
            secret = rsa_public_key_file.read()
            return self.verify_jwt_using_secret(token, secret, audience)

    def verify_jwt_using_secret(self, token, secret, audience):
        # If no audience is supplied then assume we're not verifying the audience field.
        if audience == "":
            audience = None

        try:
            return jwt.decode(token, secret, algorithms='RS256', audience=audience)
        except jwt.ExpiredSignatureError:
            self.log.error("Token has expired")
        except jwt.PyJWTError as ex:
            self.log.error("Token error - %s", ex)
        except Exception as ex:
            self.log.error("Could not decode token claims - %s", ex)
        raise web.HTTPError(403)

    def retrieve_username(self, claims, username_claim_field):
        # retrieve the username from the claims
        username = claims[username_claim_field]

        # Our system returns the username as an integer - convert to string
        if not isinstance(username, str):
            username = "%s" % username

        if "@" in username:
            # process username as if email, pull out string before '@' symbol
            return username.split("@")[0]

        else:
            # assume not username and return the user
            return username


class JSONWebTokenAuthenticator(Authenticator):
    """
    Accept the authenticated JSON Web Token from header or query parameter.
    """
    signing_certificate = Unicode(
        config=True,
        help="""
        The public certificate of the private key used to sign the incoming JSON Web Tokens.

        Should be a path to an X509 PEM format certificate filesystem.
        """
    )

    username_claim_field = Unicode(
        default_value='upn',
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """
    )

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    access_param_name = Unicode(
        config=True,
        default_value='',
        help="""The name of the query parameter used to specify the JWT access token""")

    refresh_param_name = Unicode(
        config=True,
        default_value='',
        help="""The name of the query parameter used to specify the JWT refresh token""")

    secret = Unicode(
        config=True,
        help="""Shared secret key for signing JWT token.  If defined, it overrides any setting for signing_certificate""")

    def get_handlers(self, app):
        return [
            (r'/login', JSONWebTokenLoginHandler),
        ]

    def authenticate(self, handler, data):
        raise NotImplementedError()

    async def pre_spawn_start(self, user, spawner):
        """Pass upstream_token to spawner via environment variable"""
        self.log.info("Setting auth_state environment variables")

        auth_state = await user.get_auth_state()
        if not auth_state:
            self.log.warn("Auth state was empty!")

            # Set empty strings to avoid KeyError exceptions
            spawner.environment['QCTRL_ACCESS_TOKEN'] = ''
            spawner.environment['QCTRL_REFRESH_TOKEN'] = ''
            return

        spawner.environment['QCTRL_ACCESS_TOKEN'] = auth_state['access_token']
        spawner.environment['QCTRL_REFRESH_TOKEN'] = auth_state['refresh_token']

class JSONWebTokenLocalAuthenticator(JSONWebTokenAuthenticator, LocalAuthenticator):
    """
    A version of JSONWebTokenAuthenticator that mixes in local system user creation
    """
    pass
