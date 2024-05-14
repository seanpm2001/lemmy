use crate::{
  diesel::OptionalExtension,
  newtypes::LocalUserId,
  schema::password_reset_request::dsl::{
    local_user_id,
    password_reset_request,
    published,
    token,
    valid,
  },
  source::password_reset_request::{PasswordResetRequest, PasswordResetRequestForm},
  utils::{get_conn, DbPool},
};
use diesel::{
  dsl::{insert_into, now, IntervalDsl},
  result::Error,
  sql_types::Timestamptz,
  update,
  ExpressionMethods,
  IntoSql,
  QueryDsl,
};
use diesel_async::RunQueryDsl;

impl PasswordResetRequest {
  pub async fn create(
    pool: &mut DbPool<'_>,
    from_local_user_id: LocalUserId,
    token_: String,
  ) -> Result<PasswordResetRequest, Error> {
    let form = PasswordResetRequestForm {
      local_user_id: from_local_user_id,
      token: token_,
    };
    let conn = &mut get_conn(pool).await?;
    insert_into(password_reset_request)
      .values(form)
      .get_result::<Self>(conn)
      .await
  }

  /// Reads reset token and invalidates it
  pub async fn read(pool: &mut DbPool<'_>, token_: &str) -> Result<Option<Self>, Error> {
    let conn = &mut get_conn(pool).await?;
    update(password_reset_request)
      .filter(valid.eq(true))
      .filter(token.eq(token_))
      .filter(published.gt(now.into_sql::<Timestamptz>() - 1.days()))
      .set(valid.eq(false))
      .get_result(conn)
      .await
      .optional()
  }

  pub async fn recent_count(pool: &mut DbPool<'_>, user_id: LocalUserId) -> Result<i64, Error> {
    let conn = &mut get_conn(pool).await?;
    password_reset_request
      .filter(local_user_id.eq(user_id))
      .filter(published.gt(now.into_sql::<Timestamptz>() - 1.days()))
      .count()
      .get_result(conn)
      .await
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::indexing_slicing)]
mod tests {

  use crate::{
    source::{
      instance::Instance,
      local_user::{LocalUser, LocalUserInsertForm},
      password_reset_request::PasswordResetRequest,
      person::{Person, PersonInsertForm},
    },
    traits::Crud,
    utils::build_db_pool_for_tests,
  };
  use lemmy_utils::error::LemmyResult;
  use pretty_assertions::assert_eq;
  use serial_test::serial;

  #[tokio::test]
  #[serial]
  async fn test_password_reset() -> LemmyResult<()> {
    let pool = &build_db_pool_for_tests().await;
    let pool = &mut pool.into();

    // Setup
    let inserted_instance = Instance::read_or_create(pool, "my_domain.tld".to_string()).await?;
    let new_person = PersonInsertForm::builder()
      .name("thommy prw".into())
      .public_key("pubkey".to_string())
      .instance_id(inserted_instance.id)
      .build();
    let inserted_person = Person::create(pool, &new_person).await?;
    let new_local_user = LocalUserInsertForm::builder()
      .person_id(inserted_person.id)
      .password_encrypted("pass".to_string())
      .build();
    let inserted_local_user = LocalUser::create(pool, &new_local_user, vec![]).await?;

    // Create password reset token
    let token = "nope";
    let inserted_password_reset_request =
      PasswordResetRequest::create(pool, inserted_local_user.id, token.to_string()).await?;

    // Read it and verify
    let read_password_reset_request = PasswordResetRequest::read(pool, token).await?.unwrap();
    assert_eq!(
      inserted_password_reset_request.id,
      read_password_reset_request.id
    );
    assert_eq!(
      inserted_password_reset_request.local_user_id,
      read_password_reset_request.local_user_id
    );
    assert_eq!(
      inserted_password_reset_request.token,
      read_password_reset_request.token
    );
    assert_eq!(
      inserted_password_reset_request.published,
      read_password_reset_request.published
    );

    // Check number of resets
    let reset_count = PasswordResetRequest::recent_count(pool, inserted_local_user.id).await?;
    assert_eq!(1, reset_count);

    // Cannot reuse same token again
    let read_password_reset_request = PasswordResetRequest::read(pool, token).await?;
    assert!(read_password_reset_request.is_none());

    // Cleanup
    let num_deleted = Person::delete(pool, inserted_person.id).await?;
    Instance::delete(pool, inserted_instance.id).await?;
    assert_eq!(1, num_deleted);
    Ok(())
  }
}
