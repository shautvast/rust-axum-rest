use crate::services::error::AppError;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

pub fn hash_password(password: String) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

pub fn verify_password(
    stored_hash: &PasswordHash<'_>,
    password: String,
) -> anyhow::Result<bool, AppError> {
    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), stored_hash)
        .map(|_| true)
        .map_err(|_| AppError::AuthenticationFailed)
}
