use axum::routing::{get, post};
use axum::{middleware, Extension, Router};
use dotenvy::dotenv;
use rustrest::services::posts::{get_post, get_posts};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::Level;

use rustrest::auth;
use rustrest::auth::jwt::{JwtAuth};
use rustrest::middleware::{audit_log, auth_middleware, security_headers};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    dotenv().ok();

    let url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let max_connections = env::var("MAX_DB_CONNECTIONS")
        .expect("MAX_DB_CONNECTIONS must be set")
        .parse()?;
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&url)
        .await?;

    // JWT Authentication
    let jwt_secret = env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set")
        .into_bytes();
    let jwt_auth = Arc::new(JwtAuth::new(&jwt_secret));

    // API routes
    let api_routes = Router::new()
        // Public routes
        .route("/login", post(auth::login))
        .route("/register", post(auth::register))

        // Protected routes
        .route("/posts", get(get_posts))
        .route("/posts/{id}", get(get_post))

        // Apply authentication middleware to all routes
        .layer(middleware::from_fn_with_state(Arc::clone(&jwt_auth), auth_middleware))
        .layer(middleware::from_fn(audit_log))
        .layer(middleware::from_fn(security_headers)) // Security headers
        .layer(TraceLayer::new_for_http()) // Request tracing
        .layer(Extension(Arc::clone(&jwt_auth))) // JWT auth
        .layer(Extension(pool))
        .with_state(jwt_auth).into_make_service_with_connect_info::<SocketAddr>();

    let bind_host = env::var("BIND_HOST").expect("BIND_HOST must be set");
    let addr: SocketAddr = bind_host.parse()?;
    let listener = TcpListener::bind(addr).await?;

    println!("Server is running on {}", bind_host);

    axum::serve(listener, api_routes).await?;

    Ok(())
}