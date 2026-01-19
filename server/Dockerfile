# Use a lean Python image
FROM python:3.14.2-alpine3.23
USER root
RUN apk update && apk upgrade && apk add sqlite
WORKDIR /app

# Copy and install Python requirements
COPY . .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Create the directory for the SQLite database
RUN mkdir -p /app/data

CMD ["python3", "server.py"]