# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/Techie-Tenka/reusable-services/releases/tag/v0.2.0) - 2026-10-10

### Fixed

- cargo upgrade + new Actions workflow + remove unwraps + Multipart uploads + File handlers refactors
- cargo upgrade + new Actions workflow + remove unwraps + Multipart uploads + File handlers refactors
- cargo upgrade + new Actions workflow + remove unwraps + Multipart uploads + File handlers refactors
- cargo upgrade + new Actions workflow + remove unwraps + Multipart uploads + File handlers refactors
- cargo upgrade + new Actions workflow + remove unwraps + Multipart uploads + File handlers refactors
- fix status_code in errors to be a string to fit GraphQL Hashmap

### Other

- cargo upgrade + new Actions workflow + remove unwraps + Multipart uploads + File handlers refactors
- cargo upgrade + new Actions workflow + remove unwraps + Multipart uploads + File handlers refactors
- Change runners - blacksmith
- Change runners
- Change runners
- Change runners
- Auth middleware - gRPC - return unauthorized for ACL conn failure
- Reorganize REST response body
- Email templates
- rename binary
- Surreal upgrades + Key-Bucket features in files service
- Functional API keys
- traefik tweaks
- harmonize errors
- Standardize API response. Escpecially for REST
- streamline payments
- rebuild
- rebuild
- Tighten permission handling
- Fix mistake in Actions Job for payments-service image
- Fix mistake in Actions Job for payments-service image
- Fix mistake in Actions Job for payments-service image
- email - campaigns, mailing list, subscriptions + files exif orientation
- standardize dir structure for DB to please checksum
- change Dockerfile to always include schema file
- update workflow - payments to match the rest and remove arm build for now
- Manage crates centrally
- Version bump: 0.2.0
- Harmonize API response structure - working for GraphQL
- Harmonize API response structure - working for GraphQL
- Fix issues with create_file_from_content util
- Refactor file handling to use async I/O - ditch blocking I/O + refactor all other file ops to async + add gRPC endpoint for creating file from content
- Implement currencies, including filters + Full-text search
- optimize connection.rs
- bring in payments service and remove coupled code from previous project
- change OAuth User to use internal Ids + update AdminPrivileges
- Debug middlware due to the context object AuthStatus
- Tighten permission constraints
- send AuthStatus to context instead of just user_id
- granular permissions for resources
- Switch user role
- update non-breaking crates
- add confirm authorization to gRPC
- Email Verification feature
- Cross check any probable panics that may cause broken pipes
- Cross check unwrap() handling
- Push image by manifest
- Push image by manifest
- Push image by manifest
- Push image by manifest
- Push image by manifest
- Change hardcoded GRPC endpoints to env vars in preparation for Kubernetes
- getting rid of unwraps in my code
- rename gRPC methods
- rectify longstanding gRPC OUT_DIR issue
- rectify longstanding gRPC OUT_DIR issue
- polish authentication and authorization
- switch secret key to .env
- try CI/CD ruleset again
- improve error handling
- refactor grpc services and move to lib
- Use exact tonic-build versions
- Fix some major bugs on file purchase
- Switch service-service protocol to gRPC - Use generic trait for creating gRPC clients
- add gRPC authentication middleware to handle auth for gRPC endpoints
- try different Buildx steps for diff architectures
- downgrade jwt-simple
- downgrade jwt-simple & add protobuf
- downgrade jwt-simple
- improve security by removing introspection in prod + revert to GitHub Actions default builder
- put GraphQL auth middleware on hold(async-graphql data is not being set) + improved error logging
- put GraphQL auth middleware on hold(async-graphql data is not being set) + improved error logging
- complete REST auth middleware using gRPC + Files Service implementation
- start switch to gRPC for service integration
- Add gRPC support for files service
- Finish up Email Service gRPC
- working grpc server for ACL + migration to stable Rust from Nightly
- Make it multiplatform
- Add SBOM provenance
- correct missing CI trigger
- remove comments
- add in email service
- update Docker Wasm + add in files service
- surrealDB upgrade
- on sign up return single user
- get user email endpoint
- update shared ACL service
- update pipelines and rustc
- services updates
