use std::sync::Arc;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::{header, StatusCode};
use tracing::{error, info};
use crate::auth::JwtAuth;

pub async fn auth_middleware(
    State(jwt_auth): State<Arc<JwtAuth>>,
    mut request: Request,
    next: Next
) -> Response {
    if request.uri().path() == "/login" || request.uri().path() == "/register" {
        return next.run(request).await;
    }

    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    match auth_header {
        Some(auth_value) if auth_value.starts_with("Bearer ") => {
            // Extract the token (remove "Bearer " prefix)
            let token = &auth_value[7..];

            match jwt_auth.verify_token(token) {
                Ok(claims) => {
                    info!("Authentication successful for user: {}", claims.sub);
                    request.extensions_mut().insert(claims);
                    next.run(request).await
                }
                Err(e) => {
                    error!("Token verification failed: {:?}", e);
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body("Invalid token".into())
                        .unwrap()
                }
            }
        }
        _ => {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Missing or invalid Authorization header".into())
                .unwrap()
        }
    }
}
