#!/bin/bash
docker compose stop && docker compose up -d && docker compose logs bot -f | grep -vi -E "nio|peewee"
