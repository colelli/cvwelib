FROM python:3.10-slim

WORKDIR /cvwelib

COPY ./requirements.txt .

RUN apt-get update && apt-get install -y git

RUN pip install -r requirements.txt

COPY . .

ENTRYPOINT [ "python" ]

CMD ["cvwelib.py"]