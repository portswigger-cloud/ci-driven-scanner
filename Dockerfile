ARG IMAGE_TAG=2023.7-12901

FROM public.ecr.aws/portswigger/enterprise-scan-container:${IMAGE_TAG}

USER root

COPY ./wrapper /wrapper

RUN apt-get update \
    && apt-get install software-properties-common -y \
    && add-apt-repository 'ppa:deadsnakes/ppa' \
    && apt-get install python3.10 python3.10-distutils -y \
    && apt-get clean autoclean \
    && rm -rf /var/lib/{apt,dpkg,cache,log}/

RUN python3.10 -m pip install -U pip


ENTRYPOINT ["python3.10", "/wrapper/main.py"]