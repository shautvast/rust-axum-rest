use axum::{
    extract::Request,
    middleware::Next,
    response::IntoResponse,
};
use http::{HeaderMap, HeaderName, HeaderValue};

// Enhanced security headers
pub async fn security_headers(request: Request, next: Next) -> impl IntoResponse {
    let mut response = next.run(request).await;
    
    let headers = response.headers_mut();
    
    // Prevent MIME type sniffing
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff")
    );
    
    // Prevent clickjacking
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY")
    );
    
    // Enable XSS protections
    headers.insert(
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block")
    );
    
    // Force HTTPS connections
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload")
    );
    
    // Control referrer information
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin")
    );
    
    // Content Security Policy
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    );
    
    // Permissions Policy
    headers.insert(
        HeaderName::from_static("permissions-policy"), 
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()")
    );
    
    response
}