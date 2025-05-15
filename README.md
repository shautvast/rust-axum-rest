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

| Environment Variable | Description                                      | Example Value                                    |
|----------------------|--------------------------------------------------|--------------------------------------------------|
| DATABASE_URL         | Postgres database connection URL                 | postgres://postgres:password@localhost:5432/mydb |
| MAX_DB_CONNECTIONS   | Maximum number of DB connections                 | 5                                                |
| BIND_HOST            | Address and port to bind the server              | 0.0.0.0:5001                                     |
| JWT_SECRET           | Secret used for signing JWT tokens               | supersecretkey                                   |