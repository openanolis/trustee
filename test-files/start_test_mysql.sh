#!/usr/bin/env bash
set -euo pipefail

env_file="${1:?Pass a file to receive the test database connection settings}"
MYSQL_ROOT_PASSWORD="$(openssl rand -hex 24)"
export MYSQL_ROOT_PASSWORD
MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
export MYSQL_PWD

started_at="$(date +%s)"
container="$(docker run --detach --rm --publish '127.0.0.1::3306' \
    --env MYSQL_ROOT_PASSWORD --env MYSQL_DATABASE=trustee_kbs_test \
    --health-cmd 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql --protocol=TCP -h127.0.0.1 -uroot -e "SELECT 1" >/dev/null' \
    --health-interval 2s --health-timeout 5s --health-retries 40 mysql:8.0)"
trap 'docker stop "$container" >/dev/null' EXIT

if ! status="$(timeout 120s bash -c '
    IFS= read -r event < <(docker events --since "$1" --until "$(($1 + 120))" \
        --filter type=container --filter "container=$2" \
        --filter "event=health_status: healthy" --filter "event=health_status: unhealthy" \
        --filter event=die --format "{{.Action}}")
    printf "%s\n" "$event"
' bash "$started_at" "$container")" || [[ "$status" != 'health_status: healthy' ]]; then
    printf '%s\n' 'The test MySQL container did not become healthy.' >&2
    exit 1
fi

docker exec --env MYSQL_PWD "$container" mysql --protocol=TCP -h127.0.0.1 -uroot \
    -e 'SET GLOBAL innodb_default_row_format=COMPACT'
endpoint="$(docker port "$container" 3306/tcp)"
dsn="mysql://root:$MYSQL_ROOT_PASSWORD@$endpoint/trustee_kbs_test"
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
    printf '::add-mask::%s\n' "$MYSQL_ROOT_PASSWORD" "$dsn"
fi
umask 077
printf 'MYSQL_TEST_URL=%s\nTEST_MYSQL_CONTAINER=%s\n' "$dsn" "$container" >> "$env_file"
trap - EXIT
