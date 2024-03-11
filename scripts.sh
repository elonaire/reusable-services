# for local development - start the shared service db
surreal start --log debug --user root --pass root --bind 0.0.0.0:8001 file://./services/shared-service/db-file

# for local development - start the shared service
cargo watch -x run --workdir services/shared-service

# for local development - start the ACL service db
surreal start --log debug --user root --pass root --bind 0.0.0.0:8000 file://./services/acl-service/db-file

# for local development - start the ACL service
cargo watch -x run --workdir services/acl-service


# bash function to choose which service and which db to start
function start_service() {
    if [ "$1" == "acl" ]; then
        surreal start --log debug --user root --pass root --bind

    elif [ "$1" == "shared" ]; then
        surreal start --log debug --user root --pass root --bind

    else
        echo "Invalid service name"
    fi
}
