#!/usr/bin/env bash

COMPOSE_FILE="$1"
CONTAINER_NAME="keycloak"
SUCCESS_LOG_ENTRY="Import finished successfully"
START_SECONDS="$SECONDS"
TIMEOUT="100"

success_entry_found() {
  grep -Pq "$SUCCESS_LOG_ENTRY" <<< "$("$CONT" -f "$COMPOSE_FILE" logs "$CONTAINER_NAME" 2>/dev/null)"
}

init_checks() {
  if ! [[ -r "$COMPOSE_FILE" ]]; then
    echo "cannot read compose file: '${COMPOSE_FILE}'"
    return 1
  fi
}


wait_for() {

  echo -n "waiting for ${CONTAINER_NAME}"

  while ! success_entry_found; do
    echo -n '.'
    sleep 1

    if [[ $(( SECONDS - START_SECONDS )) -gt $TIMEOUT ]]; then
      docker compose -f "$COMPOSE_FILE" logs "$CONTAINER_NAME"
      echo "$CONTAINER_NAME failed to reach ready status under $TIMEOUT seconds"
      return 1
    fi
  done

  echo -e "\n Took $(( SECONDS - START_SECONDS )) seconds"
}

init_checks || exit 1
wait_for || exit 1