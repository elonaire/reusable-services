# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/Techie-Tenka/reusable-services/releases/tag/v0.2.0) - 2026-10-10

### Fixed

- fix status_code in errors to be a string to fit GraphQL Hashmap
- fix email design

### Other

- cargo upgrade + new Actions workflow + remove unwraps + Multipart uploads + File handlers refactors
- Support non-browser clients, upgrade crates
- Email templates
- Surreal upgrades + Key-Bucket features in files service
- Functional API keys
- streamline payments
- update email primary logo var
- Tighten permission handling
- email - campaigns, mailing list, subscriptions + files exif orientation
- Configurable burst sizes
- Configurable burst sizes
- Manage crates centrally
- Need updates to be fluid
- Version bump: 0.2.0
- Rate Limiting
- Harmonize API response structure - working for GraphQL
- Harmonize API response structure - working for GraphQL
- Rectify error logs in GraphQL handler
- change logging to start of app + remove all expect from code and handle errors gracefully
- Tighten permission constraints
- update non-breaking crates
- add confirm authorization to gRPC
- Make Email Service configurable
- Email Verification feature
- Put back in dotenv().ok() - it is very very crucial
- Cross check unwrap() handling
- Add dummy liveness and readiness endpoints
- Change gRPC connection to IPV4
- Use Docker Build Cloud. Also put back cross-platform build; Man I wish WASM worked at least with async runtime
- improve error handling
- improve error handling
- refactor grpc services and move to lib
- Use exact tonic-build versions
- Switch service-service protocol to gRPC - Use generic trait for creating gRPC clients
- add gRPC authentication middleware to handle auth for gRPC endpoints
- try different Buildx steps for diff architectures
- improve security by removing introspection in prod + revert to GitHub Actions default builder
- put GraphQL auth middleware on hold(async-graphql data is not being set) + improved error logging
- start switch to gRPC for service integration
- Finish up Email Service gRPC
- Some more gRPC impls in the email service
- working grpc server for ACL + migration to stable Rust from Nightly
- update Surreal RELATION TABLES and QUERIES, Update logging to a more secure way plus persistence
- add in email service
