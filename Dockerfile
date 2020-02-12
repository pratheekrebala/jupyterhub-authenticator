FROM jupyterhub/k8s-hub:0.9.0-beta.3

USER root
RUN python3 -m pip install --upgrade pip==19.3.1 setuptools==42.0.2

USER jovyan

# RUN python3 -m pip install --user qctrl-jupyterhub-authenticator
COPY . .
RUN python3 -m pip install --user .

CMD ["jupyterhub", "--config", "/etc/jupyterhub/jupyterhub_config.py"]