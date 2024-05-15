ALTER TABLE password_reset_request
    ADD COLUMN valid bool NOT NULL DEFAULT TRUE;

