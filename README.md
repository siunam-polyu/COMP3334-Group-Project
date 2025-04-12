# COMP3334 Group Project - Uploader

## Installation

Download, install, and setup Docker Desktop (Or Docker CLI) and Docker Compose if needed: [https://docs.docker.com/compose/install/#scenario-one-install-docker-desktop](https://docs.docker.com/compose/install/#scenario-one-install-docker-desktop).

After that, you can download this project by clicking "Code" -> "[Download ZIP](https://github.com/siunam-polyu/COMP3334-Group-Project/archive/refs/heads/main.zip)" on this GitHub repository, and extract the files from the ZIP archive file.

## How to Run?

### Configuration

Before you build and run the Docker container, you are required to first setup the MFA (Multi-Factor Authentication) configuration in `src/docker-compose.yaml`.

- If you want to use Gmail's SMTP server (Default)
    - Edit environment variable `SENDER_EMAIL_ADDRESS` and `SENDER_EMAIL_PASSWORD` to your own one
- If you want to use different SMTP server
    - Add environment variable `SMTP_SERVER_DOMAIN` and/or `SMTP_SERVER_PORT`
    - Edit environment variable `SENDER_EMAIL_ADDRESS` and `SENDER_EMAIL_PASSWORD` to your own one

### Run It

After setting up MFA, you can start the web application by typing the following command to build and start the Docker container. Make sure your Docker Desktop is up and running if you're using that:

```bash
docker compose -f src/docker-compose.yaml up --build
```

After that, the web application should be running on port 443. You can access it via `https://localhost`.

### Stop It

You can stop the Docker container via the following command:

```bash
docker compose -f src/docker-compose.yaml down
```