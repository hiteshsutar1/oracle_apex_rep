-- auth_pkg.pkb - Custom Authentication Package Body
CREATE OR REPLACE PACKAGE BODY auth_pkg IS

    -- Function to validate user credentials
    FUNCTION validate_user(
        p_username       IN VARCHAR2,
        p_password       IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN BOOLEAN IS
        l_encrypted_password VARCHAR2(4000);
    BEGIN
        -- Fetch the encrypted password from the user table
        BEGIN
            SELECT encrypted_password
            INTO l_encrypted_password
            FROM users
            WHERE username = p_username;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                out_error_message := 'User not found';
                RETURN FALSE;
            WHEN OTHERS THEN
                out_error_message := SQLERRM;
                RETURN FALSE;
        END;

        -- Compare the entered password with the stored encrypted password
        IF decrypt_password(l_encrypted_password, out_error_message) = p_password THEN
            RETURN TRUE;
        ELSE
            out_error_message := 'Invalid password';
            RETURN FALSE;
        END IF;
    END validate_user;

    -- Function to encrypt a password
    FUNCTION encrypt_password(
        p_password       IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN VARCHAR2 IS
        l_encrypted_password VARCHAR2(4000);
    BEGIN
        -- Use DBMS_CRYPTO to encrypt the password
        BEGIN
            l_encrypted_password := DBMS_CRYPTO.ENCRYPT(
                src => UTL_I18N.STRING_TO_RAW(p_password, 'AL32UTF8'),
                typ => DBMS_CRYPTO.DES_CBC_PKCS5,
                key => UTL_RAW.CAST_TO_RAW('your-secret-key') -- Replace with your encryption key
            );
        EXCEPTION
            WHEN OTHERS THEN
                out_error_message := SQLERRM;
                RETURN NULL;
        END;

        RETURN RAWTOHEX(l_encrypted_password);  -- Return hex representation of encrypted password
    END encrypt_password;

    -- Function to decrypt a password
    FUNCTION decrypt_password(
        p_encrypted_password IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN VARCHAR2 IS
        l_decrypted_password VARCHAR2(4000);
        l_raw_encrypted_password RAW(4000);
    BEGIN
        -- Convert the hex back to raw before decrypting
        BEGIN
            l_raw_encrypted_password := HEXTORAW(p_encrypted_password);
        EXCEPTION
            WHEN OTHERS THEN
                out_error_message := 'Error converting hex to raw: ' || SQLERRM;
                RETURN NULL;
        END;

        -- Use DBMS_CRYPTO to decrypt the password
        BEGIN
            l_decrypted_password := UTL_I18N.RAW_TO_STRING(
                DBMS_CRYPTO.DECRYPT(
                    src => l_raw_encrypted_password,
                    typ => DBMS_CRYPTO.DES_CBC_PKCS5,
                    key => UTL_RAW.CAST_TO_RAW('your-secret-key') -- Replace with your encryption key
                ),
                'AL32UTF8'
            );
        EXCEPTION
            WHEN OTHERS THEN
                out_error_message := 'Decryption failed: ' || SQLERRM;
                RETURN NULL;
        END;

        RETURN l_decrypted_password;
    END decrypt_password;

    -- Function to create a new user with encrypted password
    FUNCTION create_user(
        p_username       IN VARCHAR2,
        p_password       IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN BOOLEAN IS
    BEGIN
        -- Check if the user already exists
        IF user_exists(p_username, out_error_message) THEN
            out_error_message := 'User already exists';
            RETURN FALSE;
        END IF;

        -- Insert new user with encrypted password
        BEGIN
            INSERT INTO users (username, encrypted_password)
            VALUES (
                p_username,
                encrypt_password(p_password, out_error_message)
            );
            COMMIT;  -- Commit the transaction
            RETURN TRUE;
        EXCEPTION
            WHEN OTHERS THEN
                out_error_message := 'Error creating user: ' || SQLERRM;
                RETURN FALSE;
        END;
    END create_user;

    -- Function to check if a user exists
    FUNCTION user_exists(
        p_username       IN VARCHAR2,
        out_error_message OUT VARCHAR2
    ) RETURN BOOLEAN IS
        l_count NUMBER;
    BEGIN
        BEGIN
            SELECT COUNT(*)
            INTO l_count
            FROM users
            WHERE username = p_username;
        EXCEPTION
            WHEN OTHERS THEN
                out_error_message := 'Error checking user existence: ' || SQLERRM;
                RETURN FALSE;
        END;

        IF l_count > 0 THEN
            RETURN TRUE;  -- User exists
        ELSE
            RETURN FALSE; -- User does not exist
        END IF;
    END user_exists;

END auth_pkg;
/
