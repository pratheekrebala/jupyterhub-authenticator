FROM jupyterhub/k8s-hub:0.8.2

USER root
RUN python3 -m pip install --upgrade pip setuptools 

USER jovyan
RUN python3 -m pip install --user qctrl-jupyterhub-authenticator 

CMD ["jupyterhub", "--config", "/etc/jupyterhub/jupyterhub_config.py"]