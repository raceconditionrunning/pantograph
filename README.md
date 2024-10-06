# Relay Photo Collector

Accept photos from teams and display them in a gallery along with extracted capture time and GPS metadata. No authentication, just basic CRUD ops on images behind unguessable URLs.

Originally created for collecting images for Race Condition Running's [Light Rail Relay 2024](https://raceconditionrunning.com/lrr24) event. Many other ways images were getting to us had metadata stripped along the way.

## Configuration

Create folders in the uploads directory for each team. The folder name will display as the team name in the interface.

You must provide a key which will be used to create unguessable URLs based on a team's name. To provide via the `URL_KEY` env var:

    echo "URL_KEY=$(openssl rand -base64 32)" > ./.env

## Usage

    docker compose up

The app will print all team URLS to the console. Share these with the teams to allow them to upload photos.

For development, invoke `app.py` directly.