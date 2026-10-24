// Published agent activity: a port of T3 Code's `infra/relay/src/agentActivity/AgentActivityRows.ts`,
// `AgentActivityPublisher.ts`, `MobileRegistrations.ts` and
// `environments/EnvironmentPublishSignatures.ts` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE).
// A publish stores the state and queues every delivery in one transaction.
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use super::Push;
use super::payloads::*;
use super::{apns, devices, fcm};
use crate::auth::dpop::Proof;
use crate::auth::dpop_proofs;
use crate::jws;
use crate::machines::linker::{registered_claims_ok, tns};
use crate::machines::{now_iso, now_ms};

/// `AgentActivityRows.listForUser`: states of the user's live links with Live Activities on.
pub async fn list_for_user(
    conn: &mut PgConnection,
    user: Uuid,
) -> Result<Vec<ActivityState>, sqlx::Error> {
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT r.state_json FROM relay_agent_activity_rows r
         JOIN relay_machine_links l ON l.machine_id = r.machine_id
                                   AND l.machine_public_key = r.machine_public_key
         WHERE l.user_id = $1 AND l.revoked_at IS NULL AND l.live_activities_enabled
         ORDER BY r.updated_at DESC",
    )
    .bind(user)
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect())
}

/// `AgentActivityRows.getForUserThread`.
pub async fn get_for_user_thread(
    conn: &mut PgConnection,
    user: Uuid,
    machine_id: &str,
    thread_id: &str,
) -> Result<Option<ActivityState>, sqlx::Error> {
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT r.state_json FROM relay_agent_activity_rows r
         JOIN relay_machine_links l ON l.machine_id = r.machine_id
                                   AND l.machine_public_key = r.machine_public_key
         WHERE l.user_id = $1 AND l.revoked_at IS NULL AND r.machine_id = $2 AND r.thread_id = $3
         ORDER BY r.updated_at DESC",
    )
    .bind(user)
    .bind(machine_id)
    .bind(thread_id)
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .find_map(|v| serde_json::from_value(v).ok()))
}

/// `AgentAwarenessDeliveryUserRecord`.
#[derive(Debug, Clone, Copy)]
pub struct DeliveryUser {
    pub user_id: Uuid,
    pub notifications_enabled: bool,
    pub live_activities_enabled: bool,
}

macro_rules! delivery_users_sql {
    ($rest:literal) => {
        concat!(
            "SELECT user_id, notifications_enabled, live_activities_enabled
             FROM relay_machine_links
             WHERE machine_id = $1 AND revoked_at IS NULL
               AND (notifications_enabled OR live_activities_enabled) ",
            $rest
        )
    };
}

fn delivery_users_of(rows: Vec<sqlx::postgres::PgRow>) -> Vec<DeliveryUser> {
    rows.iter()
        .map(|r| DeliveryUser {
            user_id: r.get(0),
            notifications_enabled: r.get(1),
            live_activities_enabled: r.get(2),
        })
        .collect()
}

/// `EnvironmentLinks.listDeliveryUsersForEnvironment`: links proven by this machine key.
pub async fn delivery_users(
    conn: &mut PgConnection,
    machine_id: &str,
    key: &str,
) -> Result<Vec<DeliveryUser>, sqlx::Error> {
    let rows = sqlx::query(delivery_users_sql!(
        "AND machine_public_key = $2 ORDER BY created_at, user_id"
    ))
    .bind(machine_id)
    .bind(key)
    .fetch_all(conn)
    .await?;
    Ok(delivery_users_of(rows))
}

/// `getForUser` + `listDeliveryUsersForEnvironment` narrowed to that user (FcmDeliveries).
pub async fn delivery_user(
    conn: &mut PgConnection,
    user: Uuid,
    machine_id: &str,
) -> Result<Option<DeliveryUser>, sqlx::Error> {
    let rows = sqlx::query(delivery_users_sql!("AND user_id = $2"))
        .bind(machine_id)
        .bind(user)
        .fetch_all(conn)
        .await?;
    Ok(delivery_users_of(rows).into_iter().next())
}

/// `EnvironmentPublishSignatures` failures.
#[derive(Debug)]
pub enum ProofError {
    Expired,
    Invalid(&'static str),
    Persistence(sqlx::Error),
}

/// `EnvironmentPublishSignatures.verify`.
pub async fn verify_publish_proof(
    push: &Push,
    issuer: &str,
    machine_id: &str,
    machine_public_key: &str,
    thread_id: &str,
    state: Option<&ActivityState>,
    proof: &str,
) -> Result<(), ProofError> {
    let invalid = || ProofError::Invalid("invalid_signature_or_payload");
    let now_s = now_ms() / 1000;
    let decoded = jws::decode_unverified(proof).ok_or_else(invalid)?;
    // T3 checks the unverified `exp` before the signature.
    if decoded
        .get("exp")
        .and_then(Value::as_f64)
        .is_some_and(|exp| exp <= now_s as f64)
    {
        return Err(ProofError::Expired);
    }
    let key = jws::verifying_key_from_pem(machine_public_key).map_err(|_| invalid())?;
    let principal = jws::machine_principal(machine_id);
    let c: Map<String, Value> = jws::verify(
        &key,
        proof,
        &jws::Expect {
            typ: jws::RELAY_ACTIVITY_PUBLISH_TYP,
            issuer: &principal,
            audience: jws::normalize_issuer(issuer),
            now_epoch_seconds: now_s,
            max_age_seconds: jws::DEFAULT_MAX_AGE_SECONDS,
        },
    )
    .map_err(|_| invalid())?;
    // `RelayAgentActivityPublishProofPayload`.
    let signed_state: Option<ActivityState> = match c.get("state") {
        Some(Value::Null) => None,
        Some(v) => Some(serde_json::from_value(v.clone()).map_err(|_| invalid())?),
        None => return Err(invalid()),
    };
    if !registered_claims_ok(&c) {
        return Err(invalid());
    }
    let ok = tns(c.get("machineId")).as_deref() == Some(machine_id)
        && tns(c.get("threadId")).as_deref() == Some(thread_id)
        && tns(c.get("sub")).as_deref() == Some(machine_id)
        && signed_state.as_ref() == state
        && state.is_none_or(|s| s.machine_id == machine_id && s.thread_id == thread_id);
    if !ok {
        return Err(invalid());
    }
    let jti = tns(c.get("jti")).expect("registered claims");
    let iat = c["iat"].as_i64().unwrap_or_default();
    let exp = c["exp"].as_i64().unwrap_or_default();
    // Vekrel's replay key (T3: `env-publish:` over environmentId/environmentPublicKey).
    let canonical =
        json!({"machineId": machine_id, "machinePublicKey": machine_public_key}).to_string();
    let thumbprint = format!(
        "machine-publish:{}",
        jws::b64url_encode(Sha256::digest(canonical.as_bytes()))
    );
    let fresh = dpop_proofs::consume(
        &push.pool,
        &Proof {
            thumbprint,
            jti,
            iat,
        },
        exp * 1000,
        now_ms(),
    )
    .await
    .map_err(ProofError::Persistence)?;
    if fresh {
        Ok(())
    } else {
        Err(ProofError::Invalid("replayed_nonce"))
    }
}

/// `AgentActivityPublisher.publish`; the deliveries, in `RelayDeliveryResult` shape.
pub async fn publish(
    push: &Push,
    machine_id: &str,
    machine_public_key: &str,
    thread_id: &str,
    state: Option<&ActivityState>,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = push.pool.begin().await?;
    match state {
        // Terminal states are kept too (pruned after 30 min) so a finished thread stays on the card.
        Some(s) => {
            sqlx::query(
                "INSERT INTO relay_agent_activity_rows (machine_id, machine_public_key, thread_id,
                    state_json, updated_at, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (machine_id, machine_public_key, thread_id)
                 DO UPDATE SET state_json = EXCLUDED.state_json, updated_at = EXCLUDED.updated_at",
            )
            .bind(machine_id)
            .bind(machine_public_key)
            .bind(&s.thread_id)
            .bind(serde_json::to_value(s).expect("json"))
            .bind(&s.updated_at)
            .bind(now_iso())
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query(
                "DELETE FROM relay_agent_activity_rows
                 WHERE machine_id = $1 AND machine_public_key = $2 AND thread_id = $3",
            )
            .bind(machine_id)
            .bind(machine_public_key)
            .bind(thread_id)
            .execute(&mut *tx)
            .await?;
        }
    }
    let now = now_ms();
    let mut out = Vec::new();
    for u in delivery_users(&mut tx, machine_id, machine_public_key).await? {
        let active = if u.live_activities_enabled {
            list_for_user(&mut tx, u.user_id).await?
        } else {
            vec![]
        };
        let terminal = state.filter(|s| s.phase.is_terminal());
        let live = u
            .live_activities_enabled
            .then(|| make_aggregate(&active, terminal, now))
            .flatten();
        let notification_only = match state {
            Some(s) if u.notifications_enabled && !u.live_activities_enabled => {
                let actives = if s.phase.is_terminal() {
                    vec![]
                } else {
                    vec![s.clone()]
                };
                make_aggregate(&actives, terminal, now)
            }
            _ => None,
        };
        for t in devices::list_targets(&mut tx, u.user_id).await? {
            if t.platform == "android" {
                out.extend(fcm::enqueue(&mut tx, push, &t, state, false).await?);
                continue;
            }
            out.extend(apns::send_for_target(&mut tx, push, &t, live.as_ref(), now, false).await?);
            if let Some(a) = &notification_only {
                out.extend(
                    apns::send_push_notification_for_target(&mut tx, push, &t, a, now).await?,
                );
            }
        }
    }
    tx.commit().await?;
    Ok(out)
}

/// `replayForLiveActivityRegistration`: repaint a (re)registered device without buzzing it.
pub async fn replay_for_registration(
    push: &Push,
    user: Uuid,
    device: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = push.pool.begin().await?;
    let states = list_for_user(&mut tx, user).await?;
    let Some(t) = devices::list_targets(&mut tx, user)
        .await?
        .into_iter()
        .find(|t| t.device_id == device)
    else {
        return Ok(());
    };
    let now = now_ms();
    if t.platform == "android" {
        fcm::enqueue(&mut tx, push, &t, None, true).await?;
    } else {
        apns::send_for_target(
            &mut tx,
            push,
            &t,
            make_aggregate(&states, None, now).as_ref(),
            now,
            true,
        )
        .await?;
    }
    tx.commit().await
}

/// `getAgentActivitySnapshot`.
pub async fn snapshot(push: &Push, user: Uuid) -> Result<Option<Aggregate>, sqlx::Error> {
    let mut conn = push.pool.acquire().await?;
    let states = list_for_user(&mut conn, user).await?;
    Ok(make_aggregate(&states, None, now_ms()))
}

/// The 5-minute housekeeping T3's cron does (`worker.ts:390-430`): prune finished rows older than
/// 30 minutes and end idle Live Activities (`endIdleLiveActivities`). Vekrel also drops finished
/// job rows (T3's queues forget delivered messages). One replica at a time.
pub async fn maintain(push: &Push) -> Result<(), sqlx::Error> {
    let mut tx = push.pool.begin().await?;
    let locked: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext('vekrel-push-maintenance'))")
            .fetch_one(&mut *tx)
            .await?;
    if !locked {
        return Ok(());
    }
    let now = now_ms();
    sqlx::query(
        "DELETE FROM relay_agent_activity_rows
         WHERE state_json ->> 'phase' IN ('completed', 'failed') AND updated_at < $1",
    )
    .bind(dpop_proofs::iso_millis(now - 30 * 60_000))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM relay_push_jobs WHERE (status = 'done' AND created_at < now() - interval '1 day')
            OR (status = 'dead' AND created_at < now() - interval '7 days')",
    )
    .execute(&mut *tx)
    .await?;
    let idle = devices::list_idle_armed_targets(
        &mut tx,
        &dpop_proofs::iso_millis(now - TERMINAL_AGENT_ACTIVITY_DISPLAY_TTL_MS),
    )
    .await?;
    let mut users: Vec<Uuid> = idle.iter().map(|(u, _)| *u).collect();
    users.sort();
    users.dedup();
    for user in users {
        if make_aggregate(&list_for_user(&mut tx, user).await?, None, now).is_some() {
            continue;
        }
        for t in devices::list_targets(&mut tx, user).await? {
            if idle.iter().any(|(u, d)| *u == user && *d == t.device_id) {
                apns::send_for_target(&mut tx, push, &t, None, now, true).await?;
            }
        }
    }
    tx.commit().await
}
