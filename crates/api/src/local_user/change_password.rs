use actix_web::web::{Data, Json};
use bcrypt::verify;
use lemmy_api_common::{
  claims::Claims,
  context::LemmyContext,
  person::{ChangePassword, LoginResponse},
  utils::{local_user_view_from_jwt, password_length_check},
};
use lemmy_db_schema::source::{local_user::LocalUser, login_token::LoginToken};
use lemmy_utils::error::{LemmyError, LemmyErrorType};

#[tracing::instrument(skip(context))]
pub async fn change_password(
  data: Json<ChangePassword>,
  context: Data<LemmyContext>,
) -> Result<Json<LoginResponse>, LemmyError> {
  let local_user_view = local_user_view_from_jwt(data.auth.as_ref(), &context).await?;

  password_length_check(&data.new_password)?;

  // Make sure passwords match
  if data.new_password != data.new_password_verify {
    Err(LemmyErrorType::PasswordsDoNotMatch)?
  }

  // Check the old password
  let valid: bool = verify(
    &data.old_password,
    &local_user_view.local_user.password_encrypted,
  )
  .unwrap_or(false);
  if !valid {
    Err(LemmyErrorType::IncorrectLogin)?
  }

  let local_user_id = local_user_view.local_user.id;
  let new_password = data.new_password.clone();
  let updated_local_user =
    LocalUser::update_password(&mut context.pool(), local_user_id, &new_password).await?;

  LoginToken::invalidate_all(&mut context.pool(), local_user_view.local_user.id).await?;

  // Return the jwt
  Ok(Json(LoginResponse {
    jwt: Some(Claims::generate(updated_local_user.id, &context).await?),
    verify_email_sent: false,
    registration_created: false,
  }))
}
