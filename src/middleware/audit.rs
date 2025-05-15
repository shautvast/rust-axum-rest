use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

// Audit logging middleware for security-relevant events
pub async fn audit_log(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let request_id = Uuid::new_v4();
    
    // Extract user information if available
    let user_id = request
        .extensions()
        .get::<crate::auth::jwt::Claims>()
        .map(|claims| claims.sub.clone())
        .unwrap_or_else(|| "anonymous".to_string());
    
    // Extract sensitive paths to log with more detail
    let is_sensitive_path = uri.path().contains("/login") || 
                           uri.path().contains("/register") || 
                           uri.path().contains("/password");
                           
    if is_sensitive_path {
        info!(
            target: "AUDIT",
            request_id = %request_id,
            remote_addr = %addr,
            method = %method,
            uri = %uri,
            user_id = %user_id,
            "Sensitive operation initiated"
        );
    }
    
    // Process the request
    let response = next.run(request).await;
    
    // Get response status for the log
    let status = response.status();
    let duration = start.elapsed();
    
    // Log authentication failures and other suspicious activity
    if status.is_client_error() || status.is_server_error() {
        warn!(
            target: "AUDIT",
            request_id = %request_id,
            remote_addr = %addr,
            method = %method,
            uri = %uri,
            user_id = %user_id,
            status = %status.as_u16(),
            duration_ms = %duration.as_millis(),
            "Request failed"
        );
    } else if is_sensitive_path {
        info!(
            target: "AUDIT",
            request_id = %request_id,
            remote_addr = %addr,
            method = %method,
            uri = %uri,
            user_id = %user_id,
            status = %status.as_u16(),
            duration_ms = %duration.as_millis(),
            "Sensitive operation completed"
        );
    }
    
    response
}