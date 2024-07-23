FROM python:3.8-alpine
COPY requirements.txt requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
RUN mkdir /logs
RUN mkdir /conf
RUN mkdir /app
COPY activity-sdl.py /app
WORKDIR /app
COPY conf conf
CMD [ "python3", "activity-sdl.py" ]