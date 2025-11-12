use serde::{Deserialize, Serialize};
use std::fmt;

use super::errors::{IntegrationError, IntegrationResult};

/// Authentication credentials for LLM services
#[derive(Clone, Serialize, Deserialize)]
pub enum Credentials {
    /// API key authentication
    ApiKey {
        /// API key value
        key: String,
        /// Optional header name (defaults to "X-API-Key")
        header_name: Option<String>,
    },
    /// Bearer token authentication
    BearerToken {
        /// Token value
        token: String,
    },
    /// Basic authentication
    Basic {
        /// Username
        username: String,
        /// Password
        password: String,
    },
    /// OAuth2 token
    OAuth2 {
        /// Access token
        access_token: String,
        /// Optional refresh token
        refresh_token: Option<String>,
        /// Token expiration timestamp (Unix epoch)
        expires_at: Option<i64>,
    },
    /// Custom authentication
    Custom {
        /// Custom header name
        header: String,
        /// Custom header value
        value: String,
    },
    /// No authentication
    None,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credentials::ApiKey { header_name, .. } => f
                .debug_struct("ApiKey")
                .field("header_name", header_name)
                .field("key", &"***REDACTED***")
                .finish(),
            Credentials::BearerToken { .. } => f
                .debug_struct("BearerToken")
                .field("token", &"***REDACTED***")
                .finish(),
            Credentials::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"***REDACTED***")
                .finish(),
            Credentials::OAuth2 {
                expires_at,
                refresh_token,
                ..
            } => f
                .debug_struct("OAuth2")
                .field("access_token", &"***REDACTED***")
                .field("refresh_token", &refresh_token.as_ref().map(|_| "***REDACTED***"))
                .field("expires_at", expires_at)
                .finish(),
            Credentials::Custom { header, .. } => f
                .debug_struct("Custom")
                .field("header", header)
                .field("value", &"***REDACTED***")
                .finish(),
            Credentials::None => write!(f, "None"),
        }
    }
}

impl Credentials {
    /// Create API key credentials
    pub fn api_key(key: impl Into<String>) -> Self {
        Credentials::ApiKey {
            key: key.into(),
            header_name: None,
        }
    }

    /// Create API key credentials with custom header
    pub fn api_key_with_header(key: impl Into<String>, header: impl Into<String>) -> Self {
        Credentials::ApiKey {
            key: key.into(),
            header_name: Some(header.into()),
        }
    }

    /// Create bearer token credentials
    pub fn bearer_token(token: impl Into<String>) -> Self {
        Credentials::BearerToken {
            token: token.into(),
        }
    }

    /// Create basic auth credentials
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        Credentials::Basic {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Create OAuth2 credentials
    pub fn oauth2(access_token: impl Into<String>) -> Self {
        Credentials::OAuth2 {
            access_token: access_token.into(),
            refresh_token: None,
            expires_at: None,
        }
    }

    /// Create custom header credentials
    pub fn custom(header: impl Into<String>, value: impl Into<String>) -> Self {
        Credentials::Custom {
            header: header.into(),
            value: value.into(),
        }
    }

    /// Apply credentials to a reqwest RequestBuilder
    pub fn apply_to_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> IntegrationResult<reqwest::RequestBuilder> {
        match self {
            Credentials::ApiKey { key, header_name } => {
                let header = header_name.as_deref().unwrap_or("X-API-Key");
                Ok(request.header(header, key))
            }
            Credentials::BearerToken { token } => Ok(request.bearer_auth(token)),
            Credentials::Basic { username, password } => {
                Ok(request.basic_auth(username, Some(password)))
            }
            Credentials::OAuth2 { access_token, .. } => Ok(request.bearer_auth(access_token)),
            Credentials::Custom { header, value } => Ok(request.header(header, value)),
            Credentials::None => Ok(request),
        }
    }

    /// Check if OAuth2 token is expired
    pub fn is_expired(&self) -> bool {
        match self {
            Credentials::OAuth2 {
                expires_at: Some(expires_at),
                ..
            } => {
                let now = chrono::Utc::now().timestamp();
                now >= *expires_at
            }
            _ => false,
        }
    }

    /// Get OAuth2 refresh token if available
    pub fn refresh_token(&self) -> Option<&str> {
        match self {
            Credentials::OAuth2 {
                refresh_token: Some(token),
                ..
            } => Some(token),
            _ => None,
        }
    }

    /// Validate credentials (basic checks)
    pub fn validate(&self) -> IntegrationResult<()> {
        match self {
            Credentials::ApiKey { key, .. } if key.is_empty() => {
                Err(IntegrationError::Configuration("API key cannot be empty".to_string()))
            }
            Credentials::BearerToken { token } if token.is_empty() => {
                Err(IntegrationError::Configuration("Bearer token cannot be empty".to_string()))
            }
            Credentials::Basic { username, password } if username.is_empty() || password.is_empty() => {
                Err(IntegrationError::Configuration("Username and password cannot be empty".to_string()))
            }
            Credentials::OAuth2 { access_token, .. } if access_token.is_empty() => {
                Err(IntegrationError::Configuration("Access token cannot be empty".to_string()))
            }
            Credentials::Custom { header, value } if header.is_empty() || value.is_empty() => {
                Err(IntegrationError::Configuration("Custom header and value cannot be empty".to_string()))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_creation() {
        let creds = Credentials::api_key("test-key");
        assert!(matches!(creds, Credentials::ApiKey { .. }));
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn test_api_key_with_custom_header() {
        let creds = Credentials::api_key_with_header("test-key", "Authorization");
        match creds {
            Credentials::ApiKey { key, header_name } => {
                assert_eq!(key, "test-key");
                assert_eq!(header_name, Some("Authorization".to_string()));
            }
            _ => panic!("Expected ApiKey variant"),
        }
    }

    #[test]
    fn test_bearer_token_creation() {
        let creds = Credentials::bearer_token("test-token");
        assert!(matches!(creds, Credentials::BearerToken { .. }));
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn test_basic_auth_creation() {
        let creds = Credentials::basic("user", "pass");
        assert!(matches!(creds, Credentials::Basic { .. }));
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn test_oauth2_creation() {
        let creds = Credentials::oauth2("access-token");
        assert!(matches!(creds, Credentials::OAuth2 { .. }));
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn test_custom_credentials() {
        let creds = Credentials::custom("X-Custom-Auth", "value");
        assert!(matches!(creds, Credentials::Custom { .. }));
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn test_validation_empty_api_key() {
        let creds = Credentials::api_key("");
        assert!(creds.validate().is_err());
    }

    #[test]
    fn test_validation_empty_basic_auth() {
        let creds = Credentials::basic("", "password");
        assert!(creds.validate().is_err());

        let creds = Credentials::basic("username", "");
        assert!(creds.validate().is_err());
    }

    #[test]
    fn test_oauth2_expiration() {
        // Not expired
        let future_time = chrono::Utc::now().timestamp() + 3600;
        let creds = Credentials::OAuth2 {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(future_time),
        };
        assert!(!creds.is_expired());

        // Expired
        let past_time = chrono::Utc::now().timestamp() - 3600;
        let creds = Credentials::OAuth2 {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(past_time),
        };
        assert!(creds.is_expired());
    }

    #[test]
    fn test_refresh_token() {
        let creds = Credentials::OAuth2 {
            access_token: "access".to_string(),
            refresh_token: Some("refresh".to_string()),
            expires_at: None,
        };
        assert_eq!(creds.refresh_token(), Some("refresh"));

        let creds = Credentials::bearer_token("token");
        assert_eq!(creds.refresh_token(), None);
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let creds = Credentials::api_key("secret-key");
        let debug_output = format!("{:?}", creds);
        assert!(!debug_output.contains("secret-key"));
        assert!(debug_output.contains("REDACTED"));
    }
}
