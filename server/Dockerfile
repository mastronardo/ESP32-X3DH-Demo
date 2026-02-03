FROM python:3.13.11-alpine3.23
USER root
RUN apk update && apk upgrade
RUN apk --no-cache add openssl ca-certificates postgresql-client
WORKDIR /app

# Copy and install Python requirements
COPY . .
RUN python3 -m venv venv-mqtt
RUN . venv-mqtt/bin/activate && pip install --upgrade pip \
    && pip install "psycopg[binary,pool]" \
    && pip install --no-cache-dir -r requirements.txt

RUN chmod +x start.sh
CMD ["/bin/sh", "/app/start.sh"]