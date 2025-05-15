use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::fmt;

use crate::services::error::AppError;
use crate::auth::jwt::Claims;

#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    User,
    Editor,
    Admin,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::User => write!(f, "user"),
            Role::Editor => write!(f, "editor"),
            Role::Admin => write!(f, "admin"),
        }
    }
}

impl From<&str> for Role {
    fn from(role: &str) -> Self {
        match role.to_lowercase().as_str() {
            "admin" => Role::Admin,
            "editor" => Role::Editor,
            _ => Role::User,
        }
    }
}

// Simple function to check if a user has a required role
pub fn has_role(claims: &Claims, required_role: &Role) -> bool {
    claims.roles
        .iter()
        .any(|r| Role::from(r.as_str()) == *required_role || Role::from(r.as_str()) == Role::Admin)
}

// Simple function to check if a user has any of the required roles
pub fn has_any_role(claims: &Claims, required_roles: &[Role]) -> bool {
    required_roles
        .iter()
        .any(|required| has_role(claims, required))
}

// Middleware for role-based authorization
pub async fn require_role(required_role: Role, request: Request, next: Next) -> impl IntoResponse {
    if let Some(claims) = request.extensions().get::<Claims>() {
        if has_role(claims, &required_role) {
            next.run(request).await
        } else {
            AppError::Forbidden(format!("Requires {} role", required_role)).into_response()
        }
    } else {
        AppError::Unauthorized("Not authenticated".to_string()).into_response()
    }
}
