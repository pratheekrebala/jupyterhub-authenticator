FROM jupyterhub/k8s-hub:0.8.2
RUN pip3 install qctrl-jupyterhub-authenticator
CMD ["jupyterhub", "--config", "/etc/jupyterhub/jupyterhub_config.py"]