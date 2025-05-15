use argon2::PasswordHash;
use crate::auth::{hash_password, verify_password};
use crate::services::error::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres, Row, postgres::PgRow};

#[derive(Debug, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub created_at: Option<DateTime<Utc>>,
}

impl<'c> sqlx::FromRow<'c, PgRow> for User {
    fn from_row(row: &'c PgRow) -> Result<Self, sqlx::Error> {
        let id: i32 = row.try_get("id")?;
        let username: String = row.try_get("username")?;
        let email: String = row.try_get("email")?;

        // Handle created_at which might be missing or in a different format
        let created_at: Option<DateTime<Utc>> = match row.try_get("created_at") {
            Ok(dt) => Some(dt),
            Err(_) => None,
        };

        Ok(User {
            id,
            username,
            email,
            created_at,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    #[serde(skip)]
    pub password: String, // Plain string password - used only for signing up
}

// Validate email format
fn is_valid_email(email: &str) -> bool {
    // Simple validation - should use a proper email validation library in production
    email.contains('@') && email.contains('.')
}

fn is_strong_password(password: &str) -> bool {
    password.len() >= 12
}

// Database functions
impl User {
    // Create a user in the database, handling both old schema (without password_hash) and new schema
    pub async fn create(
        mut new_user: NewUser,
        password: String,
        pool: &Pool<Postgres>,
    ) -> Result<Self, AppError> {
        // Validate input
        if new_user.username.len() < 3 {
            return Err(AppError::ValidationError("Username too short".to_string()));
        }

        if !is_valid_email(&new_user.email) {
            return Err(AppError::ValidationError(
                "Invalid email format".to_string(),
            ));
        }

        if !is_strong_password(&password) {
            return Err(AppError::ValidationError(
                "Password must be at least 12 characters".to_string()
            ));
        }

        new_user.password = password;

        let user =
            // Insert with password hash
            sqlx::query_as::<_, User>(
                "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at"
            )
            .bind(&new_user.username)
            .bind(&new_user.email)
            .bind(hash_password(new_user.password))
            .fetch_one(pool)
            .await;

        match user {
            Ok(user) => Ok(user),
            Err(e) => {
                // Handle constraint violations specifically
                if let sqlx::Error::Database(ref dbe) = e {
                    if let Some(constraint) = dbe.constraint() {
                        if constraint.contains("username") || constraint.contains("email") {
                            return Err(AppError::ValidationError(
                                "Username or email already exists".to_string(),
                            ));
                        }
                    }
                }

                // Other database errors become internal errors
                Err(AppError::InternalServerError)
            }
        }
    }

    pub async fn find_by_credentials(
        username: &str,
        password: String,
        pool: &Pool<Postgres>,
    ) -> anyhow::Result<Self, AppError> {
        // Get user by username
        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, email, created_at FROM users WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(pool)
        .await
        .map_err(|_| AppError::InternalServerError)?
        .ok_or(AppError::AuthenticationFailed)?;

        // If password hash exists, verify it
        let password_hash = sqlx::query_scalar::<_, Option<String>>(
            "SELECT password_hash FROM users WHERE username = $1",
        )
        .bind(username)
        .fetch_one(pool)
        .await
        .map_err(|_| AppError::InternalServerError)?
        .unwrap_or_default();
        verify_password( &PasswordHash::new(password_hash.as_str()).expect(""),password).map(|_|user)
    }

    pub async fn find_by_id(id: i32, pool: &Pool<Postgres>) -> Result<Self, AppError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, email, created_at FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|_| AppError::InternalServerError)?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

        Ok(user)
    }
}
