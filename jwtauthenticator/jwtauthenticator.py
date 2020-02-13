from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode, Bool
import jwt


class JSONWebTokenLoginHandler(BaseHandler):

    async def get(self):
        header_name = self.authenticator.header_name
        param_name = self.authenticator.param_name
        header_is_authorization = self.authenticator.header_is_authorization

        auth_header_content = self.request.headers.get(header_name, "")
        auth_cookie_content = self.get_cookie("XSRF-TOKEN", "")
        signing_certificate = self.authenticator.signing_certificate
        secret = self.authenticator.secret
        username_claim_field = self.authenticator.username_claim_field
        audience = self.authenticator.expected_audience
        tokenParam = self.get_argument(param_name, default=False)

        if auth_header_content and tokenParam:
            raise web.HTTPError(400)
        elif auth_header_content:
            if header_is_authorization:
                # we should not see "token" as first word in the AUTHORIZATION header, if we do it could mean someone coming in with a stale API token
                if auth_header_content.split()[0] != "Bearer":
                    raise web.HTTPError(403)
            else:
                token = auth_header_content
        elif auth_cookie_content:
            token = auth_cookie_content
        elif tokenParam:
            token = tokenParam
        else:
            raise web.HTTPError(401)

        claims = ""
        if secret:
            claims = self.verify_jwt_using_secret(token, secret, audience)
        elif signing_certificate:
            claims = self.verify_jwt_using_certificate(token, signing_certificate, audience)
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
                "jwt": token
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

    header_name = Unicode(
        default_value='Authorization',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""")

    header_is_authorization = Bool(
        default_value=True,
        config=True,
        help="""Treat the inspected header as an Authorization header.""")

    param_name = Unicode(
        config=True,
        default_value='access_token',
        help="""The name of the query parameter used to specify the JWT token""")

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
            return

        spawner.environment['QCTRL_TOKEN'] = auth_state['jwt']

class JSONWebTokenLocalAuthenticator(JSONWebTokenAuthenticator, LocalAuthenticator):
    """
    A version of JSONWebTokenAuthenticator that mixes in local system user creation
    """
    pass
