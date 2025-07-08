-- auth_pkg.pks - Custom Authentication Package Specification
CREATE OR REPLACE PACKAGE auth_pkg IS
    -- Function to validate user credentials
    FUNCTION validate_user(
        p_username       IN VARCHAR2,
        p_password       IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN BOOLEAN;

    -- Function to encrypt a password
    FUNCTION encrypt_password(
        p_password       IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN VARCHAR2;

    -- Function to decrypt a password
    FUNCTION decrypt_password(
        p_encrypted_password IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN VARCHAR2;

    -- Function to create a new user with encrypted password
    FUNCTION create_user(
        p_username       IN VARCHAR2,
        p_password       IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN BOOLEAN;

    -- Function to check if a user exists
    FUNCTION user_exists(
        p_username       IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN BOOLEAN;
END auth_pkg;
/
