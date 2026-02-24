# for local development - start the shared db
surreal start --log debug --bind 0.0.0.0:8000 surrealkv://./services/acl-service/db-file
