use axum::{
    http::request::Parts,
    RequestPartsExt,
    extract::FromRequestParts,
};
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use axum_extra::TypedHeader;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing;
use uuid::Uuid;

use crate::services::error::AppError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // User ID
    pub exp: i64,           // Expiration time
    pub iat: i64,           // Issued at
    pub jti: String,        // JWT ID (unique identifier)
    pub roles: Vec<String>, // User roles
}

impl Claims {
    pub fn new(user_id: String, roles: Vec<String>, expiration: Duration) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id,
            iat: now.timestamp(),
            exp: (now + expiration).timestamp(),
            jti: Uuid::new_v4().to_string(),
            roles,
        }
    }
}

#[derive(Clone)]
pub struct JwtAuth {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtAuth {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    pub fn create_token(&self, claims: &Claims) -> Result<String, AppError> {
        encode(&Header::default(), claims, &self.encoding_key)
            .map_err(|_| AppError::TokenCreation)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, AppError> {
        // Create a validation object with default settings
        let mut validation = Validation::default();
        validation.validate_exp = true; // Verify expiration time
        validation.leeway = 0; // No leeway for exp verification (default)
        
        // Decode and verify the token
        match decode::<Claims>(token, &self.decoding_key, &validation) {
            Ok(token_data) => {
                // Token is valid, return claims
                Ok(token_data.claims)
            }
            Err(e) => {
                // Log the error for debugging
                tracing::error!("Token validation error: {:?}", e);
                
                // Map jsonwebtoken errors to AppError
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(AppError::TokenExpired),
                    jsonwebtoken::errors::ErrorKind::InvalidToken => Err(AppError::InvalidToken),
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => Err(AppError::InvalidToken),
                    _ => Err(AppError::InvalidToken),
                }
            }
        }
    }
}

// Extractor for protected routes
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the Authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AppError::MissingToken)?;

        // Get our auth service from extensions
        let jwt_auth = parts
            .extensions
            .get::<Arc<JwtAuth>>()
            .ok_or(AppError::MissingAuthService)?;
            
        // Verify the token
        let claims = jwt_auth.verify_token(bearer.token())?;

        Ok(claims)
    }
}