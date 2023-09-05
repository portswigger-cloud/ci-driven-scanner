ARG IMAGE_TAG=2023.7-12901

FROM public.ecr.aws/portswigger/enterprise-scan-container:${IMAGE_TAG}

USER root

COPY ./wrapper /wrapper

RUN apt-get update \
    && apt-get install software-properties-common -y \
    && add-apt-repository 'ppa:deadsnakes/ppa' \
    && apt-get install python3.11 python3.11-distutils -y \
    && apt-get clean autoclean \
    && rm -rf /var/lib/{apt,dpkg,cache,log}

RUN python3.11 -m ensurepip --default-pip


ENTRYPOINT ["python3.10", "/wrapper/main.py"]