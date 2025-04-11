# COMP3334 Group Project - Uploader

## How to Run?

### Configuration

In `docker-compose.yaml`, change environment variables that are related to MFA. If you're planning to use Gmail's SMTP server, just change variable `SENDER_EMAIL_ADDRESS` and `SENDER_EMAIL_PASSWORD` to your own one.

### Run It

Type the following command to start the Docker container:

```bash
docker compose up --build
```

If you want to run it without Docker, type the following command to start the Flask web server:

```bash
cd src/app
sudo pip3 install -r requirements.txt
sudo flask run --port=443 --cert=../cert.pem --key=../key.pem
```