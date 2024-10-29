#!/bin/sh

docker compose -f deployments/compose.yaml down mocktitlements
docker compose -f deployments/compose.yaml up -d --build mocktitlements
npm --prefix test test