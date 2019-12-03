# FROM jupyterhub/k8s-hub:0.8.2

# USER root
# COPY . .
# RUN pip3 install -e .

# USER jovyan

FROM jupyterhub/k8s-hub:0.8.2
RUN pip3 install jupyterhub-jwtauthenticator

USER root
RUN apt-get update && apt-get install -qy vim

USER jovyan
CMD ["jupyterhub", "--config", "/etc/jupyterhub/jupyterhub_config.py"]