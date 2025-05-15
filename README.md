* REST Api based on Axum 0.8, serves as a more complete example than most blogs will provide
* Postgres database using Sqlx, including migrations
* simple datamodel and api for reading posts for a blog
* Has users and roles (roles not fully implemented)
* logging
* externalized config
* /register stores the user (passwords hashed with argon2)
* /login returns a JWT token
* /posts returns all posts
* /posts/{id} returns a post

| .env |
| DATABASE_URL=postgres://postgres:...@localhost:5432/rust-axum-rest-api |
| MAX_DB_CONNECTIONS=5 |
| BIND_HOST=0.0.0.0:5001 |
| JWT_SECRET=... |
| ALLOWED_ORIGINS= |
