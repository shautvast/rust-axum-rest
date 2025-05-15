use std::sync::Arc;
use axum::{extract::{State, Json, Extension}, http::StatusCode};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use sqlx::Pool;
use sqlx::Postgres;

use crate::services::error::AppError;
use crate::auth::jwt::{Claims, JwtAuth};
use crate::models::user::User;

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    user_id: i32,
    username: String,
}

pub async fn login(
    State(jwt_auth): State<Arc<JwtAuth>>,
    Extension(pool): Extension<Pool<Postgres>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Authentication against database
    let user = User::find_by_credentials(
        &payload.username,
        payload.password,
        &pool,
    )
    .await?;

    // Create token with appropriate roles
    let expiration = Duration::minutes(15);
    let claims = Claims::new(
        user.id.to_string(),
        vec!["user".to_string()], // Default role - in real app, fetch from database
        expiration,
    );

    let token = jwt_auth.create_token(&claims)?;

    Ok(Json(LoginResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: expiration.num_seconds(),
        user_id: user.id,
        username: user.username,
    }))
}

// Registration endpoint
#[derive(Deserialize)]
pub struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

pub async fn register(
    Extension(pool): Extension<Pool<Postgres>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<User>), AppError> {
    // Create the new user
    let new_user = crate::models::user::NewUser {
        username: payload.username,
        email: payload.email,
        password: String::new(), // Placeholder
    };

    let user = User::create(new_user, payload.password, &pool).await?;

    // Return the created user (without password)
    Ok((StatusCode::CREATED, Json(user)))
}