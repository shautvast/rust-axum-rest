use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Post {
    pub(crate) id: i32,
    pub(crate) user_id: Option<i32>,
    pub(crate) title: String,
    pub(crate) body: String,
}