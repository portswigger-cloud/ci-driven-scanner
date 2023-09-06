ARG IMAGE_TAG=2023.7-12901

FROM public.ecr.aws/portswigger/enterprise-scan-container:${IMAGE_TAG}

USER root

COPY ./wrapper /wrapper

RUN apt-get update \
    && apt-get install software-properties-common -y \
    && add-apt-repository 'ppa:deadsnakes/ppa' \
    && apt-get install python3.11 python3.11-venv -y \
    && apt-get clean autoclean \
    && rm -rf /var/lib/{apt,dpkg,cache,log}

RUN python3.11 -m ensurepip --default-pip \
    && python3.11 -m pip install -r /wrapper/requirements.txt

ENV PYTHONUNBUFFERED 1

ENTRYPOINT ["python3.11", "/wrapper/main.py"]