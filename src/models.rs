use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize)]
pub struct TokenAuthorizerEvent {
    #[serde(rename = "authorizationToken")]
    pub authorization_token: String,
    #[serde(rename = "methodArn")]
    pub method_arn: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyStatement {
    #[serde(rename = "Action")]
    pub action: String,
    #[serde(rename = "Effect")]
    pub effect: String,
    #[serde(rename = "Resource")]
    pub resource: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyDocument {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Statement")]
    pub statement: Vec<PolicyStatement>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenAuthorizerResponse {
    #[serde(rename = "principalId")]
    pub principal_id: String,
    #[serde(rename = "policyDocument")]
    pub policy_document: PolicyDocument,
    pub context: HashMap<String, String>,
}

fn claim_as_string(token_claims: &Value, claim_name: &str) -> Option<String> {
    token_claims.get(claim_name).and_then(|value| {
        if value.is_null() {
            return None;
        }

        Some(
            value
                .as_str()
                .map(|claim_value| claim_value.to_string())
                .unwrap_or_else(|| value.to_string()),
        )
    })
}

impl TokenAuthorizerResponse {
    #[inline]
    pub fn allow(principal_id: &str, token_claims: &Value, context_claims: &[String]) -> Self {
        let mut context = HashMap::new();
        context.insert(
            "jwtClaims".to_string(),
            serde_json::to_string(token_claims).unwrap(),
        );

        // For API Gateway REST APIs, mimic support for $context.authorizer.claims.property
        // that API Gateway provides for HTTP APIs
        //
        // See https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging-variables.html
        for claim_name in context_claims {
            if let Some(claim_value) = claim_as_string(token_claims, claim_name) {
                context.insert(format!("claims.{}", claim_name), claim_value);
            }
        }

        Self {
            context,
            principal_id: principal_id.to_string(),
            policy_document: PolicyDocument {
                version: "2012-10-17".to_string(),
                statement: vec![PolicyStatement {
                    effect: "Allow".to_string(),
                    action: "execute-api:Invoke".to_string(),
                    // NOTE: this is intentionally open to avoid cache conflicts
                    //   when enabling cache and using multiple endpoints.
                    //   For more details you can read: https://www.alexdebrie.com/posts/lambda-custom-authorizers/#caching-across-multiple-functions
                    resource: "*".to_string(),
                }],
            },
        }
    }

    #[inline]
    pub fn deny(resource: &str) -> Self {
        Self {
            context: HashMap::new(),
            principal_id: "none".to_string(),
            policy_document: PolicyDocument {
                version: "2012-10-17".to_string(),
                statement: vec![PolicyStatement {
                    effect: "Deny".to_string(),
                    action: "execute-api:Invoke".to_string(),
                    resource: resource.to_string(),
                }],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn it_should_create_an_allow_response() {
        let principal_id = "John Doe";
        let token_claims = json!({
            "iat": 1516239022,
            "name": "John Doe",
            "email": "john.doe@example.com"
        });
        let context_claims = vec!["email".to_string()];
        let response = TokenAuthorizerResponse::allow(principal_id, &token_claims, &context_claims);

        assert_eq!(response.principal_id, "John Doe");
        assert_eq!(
            response.policy_document.statement.first().unwrap().effect,
            "Allow"
        );
        assert_eq!(
            response.context.get("claims.email"),
            Some(&"john.doe@example.com".to_string())
        );
        let embedded_claims =
            serde_json::from_str::<Value>(response.context.get("jwtClaims").unwrap())
                .expect("valid jwtClaims JSON");
        assert_eq!(embedded_claims, token_claims);
    }

    #[test]
    fn it_should_support_email_claim() {
        let principal_id = "John Doe";
        let token_claims = json!({
            "email": "john.doe@example.com"
        });
        let context_claims = vec!["email".to_string()];
        let response = TokenAuthorizerResponse::allow(principal_id, &token_claims, &context_claims);

        assert_eq!(
            response.context.get("claims.email"),
            Some(&"john.doe@example.com".to_string())
        );
    }

    #[test]
    fn it_should_emit_only_configured_claims() {
        let principal_id = "John Doe";
        let token_claims = json!({
            "email": "john.doe@example.com",
            "name": "John Doe"
        });
        let context_claims = vec!["email".to_string()];
        let response = TokenAuthorizerResponse::allow(principal_id, &token_claims, &context_claims);

        assert_eq!(
            response.context.get("claims.email"),
            Some(&"john.doe@example.com".to_string())
        );
        assert!(!response.context.contains_key("claims.name"));
    }

    #[test]
    fn it_create_a_deny_response() {
        let resource = "arn::some:resource";
        let response = TokenAuthorizerResponse::deny(resource);
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({
                "context": {},
                "policyDocument": {
                    "Statement": [
                        {
                            "Action": "execute-api:Invoke",
                            "Effect": "Deny",
                            "Resource": "arn::some:resource"
                        }
                    ],
                    "Version": "2012-10-17"
                },
                "principalId": "none"
            })
        );
    }
}
