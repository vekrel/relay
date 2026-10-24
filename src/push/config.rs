// Push settings (T3 `infra/relay/src/worker.ts:141-157`, `Config.ts` ApnsCredentials). Keys are
// `Secret`s: `Debug` and every error message leave them out.
//
// Vekrel splits T3's one switch in two: credentials decide whether jobs are queued at all (T3's
// `config.apns` / `fcmServiceAccount`), and `APNS_ENABLED` / `FCM_ENABLED` (default true, as T3)
// pause delivery while queued jobs wait. Without credentials the relay answers as T3 does with
// push off, so a deploy without keys still boots.
use crate::config::Secret;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsEnvironment {
    Sandbox,
    Production,
}

impl ApnsEnvironment {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sandbox" => Some(Self::Sandbox),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApnsCredentials {
    pub team_id: String,
    pub key_id: String,
    /// The `.p8` (PKCS#8 PEM, P-256); literal `\n` allowed as in T3.
    pub private_key: Secret,
    pub bundle_id: String,
    pub environment: ApnsEnvironment,
}

#[derive(Debug, Clone)]
pub struct ServiceAccount {
    pub project_id: String,
    pub client_email: String,
    pub private_key: Secret,
}

#[derive(Debug, Clone)]
pub struct PushConfig {
    pub apns: Option<ApnsCredentials>,
    pub apns_enabled: bool,
    /// `APNS_API_BASE`: replaces both Apple hosts (tests point it at a fake).
    pub apns_api_base: Option<String>,
    pub fcm: Option<ServiceAccount>,
    pub fcm_enabled: bool,
    /// `FCM_API_BASE`, default `https://fcm.googleapis.com`.
    pub fcm_api_base: String,
    /// `FCM_TOKEN_URL`, default `https://oauth2.googleapis.com/token`.
    pub fcm_token_url: String,
    /// `APNS_BUNDLE_IDS` (comma list, default `APNS_BUNDLE_ID`): the bundle ids a device may
    /// register as its APNs topic. Vekrel, not T3 (T3 takes any): our key could otherwise push to
    /// any app of the team.
    pub apns_bundle_ids: Vec<String>,
    /// `FCM_PACKAGE_NAMES` (comma list, required with `FCM_SERVICE_ACCOUNT`): the Android packages
    /// a device may register (`restricted_package_name`). Vekrel, not T3.
    pub fcm_package_names: Vec<String>,
}

fn list(v: Option<String>) -> Vec<String> {
    v.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn flag(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<bool, String> {
    match get(name).as_deref() {
        None | Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(other) => Err(format!("{name} must be true or false: {other:?}")),
    }
}

impl PushConfig {
    pub fn from_lookup(get: &impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let val = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let names = [
            "APNS_TEAM_ID",
            "APNS_KEY_ID",
            "APNS_BUNDLE_ID",
            "APNS_PRIVATE_KEY",
            "APNS_ENVIRONMENT",
        ];
        let set: Vec<Option<String>> = names.iter().map(|n| val(n)).collect();
        let apns = if set.iter().all(Option::is_none) {
            None
        } else if let [
            Some(team_id),
            Some(key_id),
            Some(bundle_id),
            Some(key),
            Some(env),
        ] = &set[..]
        {
            let environment = ApnsEnvironment::parse(env).ok_or_else(|| {
                format!("APNS_ENVIRONMENT must be sandbox or production: {env:?}")
            })?;
            super::apns::signing_key(key)
                .map_err(|_| "APNS_PRIVATE_KEY is not a P-256 PKCS#8 PEM key")?;
            Some(ApnsCredentials {
                team_id: team_id.clone(),
                key_id: key_id.clone(),
                private_key: Secret(key.clone()),
                bundle_id: bundle_id.clone(),
                environment,
            })
        } else {
            return Err(format!("set all of {} or none", names.join(", ")));
        };
        let fcm = match val("FCM_SERVICE_ACCOUNT") {
            None => None,
            Some(json) => Some(
                super::fcm::service_account(&json)
                    .ok_or("FCM_SERVICE_ACCOUNT is not a service-account JSON with project_id, client_email and an RSA private_key")?,
            ),
        };
        let mut apns_bundle_ids = list(val("APNS_BUNDLE_IDS"));
        if let Some(a) = &apns
            && apns_bundle_ids.is_empty()
        {
            apns_bundle_ids.push(a.bundle_id.clone());
        }
        let fcm_package_names = list(val("FCM_PACKAGE_NAMES"));
        if fcm.is_some() && fcm_package_names.is_empty() {
            return Err("FCM_SERVICE_ACCOUNT needs FCM_PACKAGE_NAMES (the Android package names devices may register)".into());
        }
        Ok(Self {
            apns_bundle_ids,
            fcm_package_names,
            apns,
            apns_enabled: flag(get, "APNS_ENABLED")?,
            apns_api_base: val("APNS_API_BASE").map(|b| b.trim_end_matches('/').to_owned()),
            fcm,
            fcm_enabled: flag(get, "FCM_ENABLED")?,
            fcm_api_base: val("FCM_API_BASE")
                .unwrap_or_else(|| "https://fcm.googleapis.com".into())
                .trim_end_matches('/')
                .to_owned(),
            fcm_token_url: val("FCM_TOKEN_URL")
                .unwrap_or_else(|| "https://oauth2.googleapis.com/token".into()),
        })
    }
}

impl PushConfig {
    /// Whether a device's own bundle id / package may route its pushes. Without credentials
    /// nothing is sent, so anything is kept until an operator configures the list.
    pub fn app_allowed(&self, platform: &str, app: Option<&str>) -> bool {
        let Some(app) = app else { return true };
        if platform == "android" {
            self.fcm.is_none() || self.fcm_package_names.iter().any(|p| p == app)
        } else {
            self.apns.is_none() || self.apns_bundle_ids.iter().any(|b| b == app)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn load(vars: &[(&str, &str)]) -> Result<PushConfig, String> {
        let m: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        PushConfig::from_lookup(&|k: &str| m.get(k).cloned())
    }

    #[test]
    fn push_settings() {
        let c = load(&[]).unwrap();
        assert!(c.apns.is_none() && c.fcm.is_none() && c.apns_enabled && c.fcm_enabled);
        assert_eq!(c.fcm_api_base, "https://fcm.googleapis.com");
        assert!(
            load(&[("APNS_TEAM_ID", "T")])
                .unwrap_err()
                .contains("set all of")
        );
        assert!(load(&[("APNS_ENABLED", "no")]).is_err());
        assert!(!load(&[("FCM_ENABLED", "false")]).unwrap().fcm_enabled);
        let secret = "-----BEGIN PRIVATE KEY-----\nnot-a-key-SECRET\n-----END PRIVATE KEY-----";
        let err = load(&[
            ("APNS_TEAM_ID", "T"),
            ("APNS_KEY_ID", "K"),
            ("APNS_BUNDLE_ID", "b"),
            ("APNS_PRIVATE_KEY", secret),
            ("APNS_ENVIRONMENT", "sandbox"),
        ])
        .unwrap_err();
        assert!(!err.contains("SECRET"), "{err}");
        let err = load(&[(
            "FCM_SERVICE_ACCOUNT",
            r#"{"project_id":"p","client_email":"e","private_key":"SECRET"}"#,
        )])
        .unwrap_err();
        assert!(!err.contains("SECRET"), "{err}");
    }
}
