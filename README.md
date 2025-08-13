# Welcome to the Techie Tenka Shared 🌱 GraphQL services!

## Getting Started 🚀
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. The architecture of the project is microservices monorepo. Each service is in its own directory with its own dependencies. All the shared functionality and models are in the library crate `lib` in the root directory of the project.
### Prerequisites / Installations 👨🏽‍💻
- [Rust](https://www.rust-lang.org/tools/install)
- [SurrealDB](https://surrealdb.com/install)

### Running individual services on local 🏃🏽‍♂️
- Clone the repo
- Start SurrealDB using the command: `surreal start --log debug --bind 0.0.0.0:8000 surrealkv://./services/<service_directory>/db-file` in the root directory of the project.\
e.g. `surreal start --log debug  --bind 0.0.0.0:8000 surrealkv://./services/acl-service/db-file` will start the ACL service database.
- Ask the Lead Engineer for the `.env` file and place it in the root directory of the project. **N/B**: The `.env` file is not committed to the repository for security reasons. It has the database credentials and other sensitive information.
- Run any service using the command: `bacon run-<service>` in the root directory. This will start the server and restart it whenever you make changes to the code.\
e.g. `bacon run-acl` will start the ACL service.\
**N/B**: The `bacon run-<service>` commands are in the `bacon.toml` file located in the root directory of the project.\
Cargo will automatically install any dependencies that are missing.

#### Testing the service endpoints 🧪(for individual services)
We are using GraphQL for our API. You can use any GraphQL client to test the endpoints.\
By default, there is a GraphQL playground available at `http://localhost:<PORT>` for each service.\
e.g. `http://localhost:3001` for the ACL service.

### Running all(multi-container) services on local 🏃🏽‍♂️
- Clone the repo
- Install [Docker](https://docs.docker.com/get-docker/)
- Install [Docker Compose](https://docs.docker.com/compose/install/)
- Ask the Lead Engineer for the `.env` file and place it in the root directory of the project. **N/B**: The `.env` file is not committed to the repository for security reasons. It has the database credentials and other sensitive information.
- Run `docker-compose -f docker-compose.yml [-f docker-compose.<other_service>.yml] up --build`.\
e.g. `docker-compose -f docker-compose.yml -f docker-compose.acl-service.yml up --build` will build and start a multi-container setup that includes the API gateway, the ACL service and its database.\
OR `docker-compose -f docker-compose.yml -f docker-compose.acl-service.yml -f docker-compose.shared-service.yml up --build` will build and start a multi-container setup with the ACL service, the Shared service and their respective databases.\
**N/B**: The order of the files in the command is important. The first file is the main file and the other files are overrides. The overrides are used to add more services to the main file. So you can spin up as many services as you want by adding their respective override files to the command.

#### Testing the service endpoints 🧪(for multi-container services)
We are using GraphQL for our API. You can use any GraphQL client to test the endpoints.\
By default, there is a GraphQL playground available at `http://localhost/<upstream_service>` for each service.\
e.g. `http://localhost/acl-service` for the ACL service.
This is because we are using an API gateway. The API gateway is the entry point to the system. It routes requests to the respective services. You can find the upstream services in the `nginx/nginx.conf` file.\
**N/B**: `http://localhost:<PORT>` also works on local but will not work with SSL termination in the API gateway in production. We will then use `https://example.com/<upstream_service>`.

## Contributing 🤝🏽
Every authorized contributor is allowed to contribute to the repository whether by adding features, bug fixing or participating in code reviews. All code reviews are done on GitHub by the Lead Engineer.

### Branching 🌳
- The `main` branch is the default branch and is protected. No one is allowed to push directly to the `main` branch.

- The `dev` branch is the development branch. All work should be done on the `dev` branch. The `dev` branch is protected. No one is allowed to push directly to the `dev` branch.

- All work should be done on a separate branch. The branch name should be in the format: `feature/<feature_name>` or `bug/<bug_name>`

- When you are done with your work, create a pull request to the `dev` branch. The pull request should be in the format: `feature/<feature_name>` or `bug/<bug_name>`

- The Lead Engineer will review the pull request and merge it to the `dev` branch if it is approved.
**N/B**: This might change in future because of automated code reviews or streamlined pipelines.
- The Lead Engineer will merge the `dev` branch to the `main` branch when a new release is ready.

## License 📝
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments 🙏🏽
- [SurrealDB](https://surrealdb.com)
- [Rust](https://www.rust-lang.org/)
- [GraphQL](https://graphql.org/)
- [Async-graphql](https://async-graphql.github.io/async-graphql/en/introduction.html)
- [Axum](https://github.com/tokio-rs/axum)
- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Nginx](https://www.nginx.com/)

## Authors ✍🏽
- [Elon Aseneka Idiong'o](https://github.com/elonaire)
