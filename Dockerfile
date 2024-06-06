From ubuntu

RUN apt update -y
RUN apt install python3-pip -y

COPY KubePWN/ /KubePWN
RUN pip3 install -r /KubePWN/requirements.txt
RUN pip3 install -r /KubePWN/web-ui/requirements.txt

COPY kubectl /bin/kubectl
