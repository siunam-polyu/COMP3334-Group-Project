FROM python:3.11-alpine

WORKDIR /app
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

COPY ./src .
RUN pip3 install requests flask gunicorn

RUN chown -R root:root /app && \
    chmod -R 755 /app

RUN adduser -S www-data -G www-data -u 1000
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "app:app", "-b 0.0.0.0:5000", "--user", "www-data", "--group", "www-data"]