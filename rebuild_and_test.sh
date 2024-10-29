#!/bin/sh

podman compose -f deployments/compose.yaml down mocktitlements
podman compose -f deployments/compose.yaml up -d --build mocktitlements
npm --prefix test test