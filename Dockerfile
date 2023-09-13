ARG IMAGE_TAG=2023.7-12901

FROM public.ecr.aws/portswigger/enterprise-scan-container:${IMAGE_TAG}

USER root

RUN apt-get update \
    && apt-get install software-properties-common -y \
    && add-apt-repository 'ppa:deadsnakes/ppa' \
    && apt-get install python3.11 python3.11-venv -y \
    && apt-get clean autoclean \
    && rm -rf /var/lib/{apt,dpkg,cache,log}

COPY ./src /app/src
COPY ./README.md /app/README.md
COPY ./LICENSE /app/LICENSE
COPY ./pyproject.toml /app/pyproject.toml

WORKDIR /app

RUN python3.11 -m ensurepip --default-pip \
    && python3.11 -m pip install .

ENV PYTHONUNBUFFERED 1

ENTRYPOINT ["burp_wrapper"]