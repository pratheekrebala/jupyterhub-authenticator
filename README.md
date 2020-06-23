# Q-CTRL JupyterHub Authenticator

Authenticate to JupyterHub using a query parameter for the JSONWebToken, or by an authenticating proxy that can set the Authorization header with the content of a JSON Web Token.

Originally forked from [mogthesprog/jwtauthenticator](https://github.com/mogthesprog/jwtauthenticator) with the following modifications thus far:

- Changed next URL on login to spawn notebook instance rather than going to home.
- Added ability to use an int value for user_id claim.
- Replaced python-jose with pyjwt which is used internally.
- Moved onto Poetry instead of setup.py
- Added Dockerfile for zero-to-jupyterhub Hub.
- Added CI/CD pipelines

Deployed to our JupyterHub instance using [Zero to JupyterHub](https://zero-to-jupyterhub.readthedocs.io). Our ingress has currently been modified to strip Content-Security-Protection headers to allow inclusion in any iframe. This will need to be modified for production.

Deployment configuration for the environment this is currently being served from [is here](https://github.com/qctrl/jupyterhub-deploy/tree/master/front-end-research).

## Table of contents

- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

## Installation

This package can be installed with pip:

```bash
pip install qctrl-jupyterhub-authenticator
```

For the Q-CTRL instances however, it is baked into a [Docker image](https://hub.docker.com/repository/docker/qctrl/jupyterhub-authenticator), which is then deployed [via a helm chart](https://github.com/qctrl/jupyterhub-deploy/blob/master/app-prod/apply-changes.sh#L22) in place of the standard [jupyterhub/k8s-hub](https://hub.docker.com/r/jupyterhub/k8s-hub) image.

### Cluster installation

You'll need:

- A Kubernetes cluster (Docker for mac will do for local testing)
- Helm v3.0+
- Kubectl
- gettext

### Configuration

Configuration of this authenticator is done in the [JupyterHub Helm Chart values](https://github.com/qctrl/jupyterhub-deploy/blob/master/front-end-research/config.yaml).

You'll need to set some configuration options including the location of the signing certificate (in PEM format), field containing the userPrincipalName or sAMAccountName/username, and the expected audience of the JSONWebToken. This last part is optional, if you set audience to an empty string then the authenticator will skip the validation of that field.

```bash
# one of "secret" or "signing_certificate" must be given.  If both, then "secret" will be the signing method used.
c.JSONWebTokenAuthenticator.secret = '<insert-256-bit-secret-key-here>'            # The secrect key used to generate the given token
# -OR-
c.JSONWebTokenAuthenticator.signing_certificate = '/foo/bar/adfs-signature.crt'    # The certificate used to sign the incoming JSONWebToken, must be in PEM Format

c.JSONWebTokenAuthenticator.username_claim_field = 'upn'                           # The claim field contianing the username/sAMAccountNAme/userPrincipalName
c.JSONWebTokenAuthenticator.expected_audience = 'https://myApp.domain.local/'               # This config option should match the aud field of the JSONWebToken, empty string to disable the validation of this field.
#c.JSONWebLocalTokenAuthenticator.create_system_users = True                       # This will enable local user creation upon authentication, requires JSONWebTokenLocalAuthenticator
#c.JSONWebTokenAuthenticator.header_name = 'Authorization'                         # default value
```

Within Q-CTRL, configuration values are provided in the [Helm values file](https://github.com/qctrl/jupyterhub-deploy/blob/master/app-prod/config.yaml).

## Contributing

See [Contributing](https://github.com/qctrl/.github/blob/master/CONTRIBUTING.md).

## Credits

See [Contributors](https://github.com/qctrl/jupyterhub-authenticator/graphs/contributors).

## License

See [LICENSE](LICENSE).
