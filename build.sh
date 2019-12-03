#!/bin/bash
docker build -t qctrl/jupyterhub-k8s-hub:0.8.2 --progress=plain .
docker push qctrl/jupyterhub-k8s-hub:0.8.2
