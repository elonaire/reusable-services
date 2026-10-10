# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/Techie-Tenka/reusable-services/releases/tag/v0.2.0) - 2026-10-10

### Fixed

- fix status_code in errors to be a string to fit GraphQL Hashmap
- fix status_code in errors to be a string to fit GraphQL Hashmap

### Other

- cargo upgrade + new Actions workflow + remove unwraps + Multipart uploads + File handlers refactors
- Support non-browser clients, upgrade crates
- change LICENSE
- Remove migrations
- Add original file name to uploaded file response
- rectify bucket owner
- Surreal upgrades + Key-Bucket features in files service
- Standardize API response. Escpecially for REST
- streamline payments
- Tighten permission handling
- email - campaigns, mailing list, subscriptions + files exif orientation
- Image resize feature
- Configurable burst sizes
- Manage crates centrally
- Need updates to be fluid
- Version bump: 0.2.0
- Rate Limiting
- Fix issues with create_file_from_content util
- Refactor file handling to use async I/O - ditch blocking I/O + refactor all other file ops to async + add gRPC endpoint for creating file from content
- optimize connection.rs
- Rectify error logs in GraphQL handler
- change logging to start of app + remove all expect from code and handle errors gracefully
- Debug middlware due to the context object AuthStatus
- Switch user role
- Fix critical file service bugs
- update non-breaking crates
- add confirm authorization to gRPC
- rectify multiple file uploads bug
- update uploaded file response to include system file name
- Cross check any probable panics that may cause broken pipes
- Put back in dotenv().ok() - it is very very crucial
- Cross check unwrap() handling
- Add dummy liveness and readiness endpoints
- Change gRPC connection to IPV4
- Use Docker Build Cloud. Also put back cross-platform build; Man I wish WASM worked at least with async runtime
- Tighten record checks
- improve error handling
- improve error handling
- refactor grpc services and move to lib
- Migrate created_at to READONLYs
- Use exact tonic-build versions
- Fix some major bugs on file purchase
- Switch service-service protocol to gRPC - Use generic trait for creating gRPC clients
- add gRPC authentication middleware to handle auth for gRPC endpoints
- try different Buildx steps for diff architectures
- handle errors better in files db connection
- improve security by removing introspection in prod + revert to GitHub Actions default builder
- put GraphQL auth middleware on hold(async-graphql data is not being set) + improved error logging
- put GraphQL auth middleware on hold(async-graphql data is not being set) + improved error logging
- complete REST auth middleware using gRPC + Files Service implementation
- start switch to gRPC for service integration
- Add gRPC support for files service
- Finish up Email Service gRPC
- working grpc server for ACL + migration to stable Rust from Nightly
- update Surreal RELATION TABLES and QUERIES, Update logging to a more secure way plus persistence
- update Docker Wasm + add in files service
