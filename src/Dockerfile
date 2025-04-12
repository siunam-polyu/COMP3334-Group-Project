FROM python:3.11-alpine

WORKDIR /app
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# generate self-signed certificate for HTTPS
RUN apk update && \
    apk add openssl && \
    openssl req -x509 -newkey rsa:4096 -nodes -out /cert.pem -keyout /key.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com" && \
    chmod 755 /cert.pem /key.pem

COPY ./app .
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN rm -f /app/*.db /app/requirements.txt

# set the timezone to Hong Kong. otherwise the MFA verification code will be expired
RUN ln -s /usr/share/zoneinfo/Hongkong /etc/localtime

# hardening
RUN chown -R root:root /app && \
    chmod -R 1777 /app && \
    chmod -R 755 /app/static /app/templates /app/utils /app/*.py && \
    rm -rf /app/uploads && mkdir /app/uploads && chmod -R 1777 /app/uploads

RUN adduser -S www-data -G www-data -u 1000
USER www-data
EXPOSE 5000
CMD ["flask", "run", "--port=443", "--cert=/cert.pem", "--key=/key.pem"]