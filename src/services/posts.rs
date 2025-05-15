use crate::models::post::Post;
use axum::http::StatusCode;
use axum::{Extension, Json};
use axum::extract::Path;
use sqlx::{query_as, Pool, Postgres};

pub async fn get_posts(
    Extension(pool): Extension<Pool<Postgres>>,
) -> Result<Json<Vec<Post>>, StatusCode> {
    let posts = query_as!(Post, "SELECT id, user_id, title, body FROM posts")
        .fetch_all(&pool)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(posts))
}

pub async fn get_post(
    Extension(pool): Extension<Pool<Postgres>>, 
    Path(id): Path<i32>
) -> Result<Json<Post>, StatusCode>  {
    let post = query_as!(Post, "SELECT id, user_id, title, body FROM posts WHERE id = $1", id)
        .fetch_one(&pool)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(post))
}