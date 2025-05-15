// src/error.rs
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;
use tracing::error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Token creation error")]
    TokenCreation,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Missing authentication token")]
    MissingToken,

    #[error("Missing auth service")]
    MissingAuthService,

    #[error("Internal server error")]
    InternalServerError,
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::AuthenticationFailed => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::TokenCreation => {
                error!("Failed to create token: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            },
            AppError::InvalidToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::TokenExpired => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::MissingToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::MissingAuthService => {
                error!("Auth service missing: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            },
            AppError::InternalServerError => {
                error!("Internal server error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            },
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::DatabaseError(msg) => {
                error!("Database error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            },
        };

        // Hide internal details from response for security
        let public_message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "An internal error occurred. Please try again later.".to_string()
        } else {
            error_message
        };

        let body = Json(json!({
            "error": public_message,
        }));

        (status, body).into_response()
    }
}