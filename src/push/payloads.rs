// Agent-activity shapes and the pure rules over them: a port of T3 Code's
// `infra/relay/src/agentActivity/agentActivityAggregate.ts`, `agentActivityPayloads.ts`,
// `agentActivityAlerts.ts` and `fcmPayloads.ts` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE),
// plus the Android alert builders of `FcmDeliveries.ts`. Shapes follow Vekrel-Shared
// `contracts/src/relay.ts` ("environment" is "machine"). Lengths are JS string lengths (UTF-16).
// Payloads carry what T3's do: ids, phases, statuses and the project/thread/model titles the
// machine publishes; never message or turn content.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::machines::parse_iso_ms;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Starting,
    Running,
    WaitingForApproval,
    WaitingForInput,
    Completed,
    Failed,
    Stale,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::WaitingForApproval => "waiting_for_approval",
            Self::WaitingForInput => "waiting_for_input",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Stale => "stale",
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
    fn is_attention(self) -> bool {
        matches!(self, Self::WaitingForApproval | Self::WaitingForInput)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `TrimmedNonEmptyString`, trimmed as JS `trim` does (titles reach the phone as decoded here).
pub fn tns<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    let t = js_trim(&s);
    if t.is_empty() {
        return Err(serde::de::Error::custom("blank string"));
    }
    Ok(t.to_owned())
}

pub fn opt_tns<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    tns(d).map(Some)
}

/// `RelayAgentActivityState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityState {
    #[serde(deserialize_with = "tns")]
    pub machine_id: String,
    #[serde(deserialize_with = "tns")]
    pub thread_id: String,
    #[serde(deserialize_with = "tns")]
    pub project_title: String,
    #[serde(deserialize_with = "tns")]
    pub thread_title: String,
    pub phase: Phase,
    #[serde(deserialize_with = "tns")]
    pub headline: String,
    #[serde(
        default,
        deserialize_with = "opt_tns",
        skip_serializing_if = "Option::is_none"
    )]
    pub detail: Option<String>,
    #[serde(deserialize_with = "tns")]
    pub model_title: String,
    #[serde(deserialize_with = "tns")]
    pub updated_at: String,
    #[serde(deserialize_with = "tns")]
    pub deep_link: String,
}

/// `RelayAgentActivityAggregateRow`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateRow {
    pub machine_id: String,
    pub thread_id: String,
    pub project_title: String,
    pub thread_title: String,
    pub model_title: String,
    pub phase: Phase,
    pub status: String,
    pub updated_at: String,
    pub deep_link: String,
}

/// `RelayAgentActivityAggregateState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Aggregate {
    pub title: String,
    pub subtitle: String,
    pub active_count: i64,
    pub updated_at: String,
    pub activities: Vec<AggregateRow>,
}

/// `RelayAgentAwarenessPreferences`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    pub live_activities_enabled: bool,
    pub notifications_enabled: bool,
    pub notify_on_approval: bool,
    pub notify_on_input: bool,
    pub notify_on_completion: bool,
    pub notify_on_failure: bool,
}

/// `ApnsNotificationPayload` (`apnsDeliveryJobs.ts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    pub title: String,
    pub body: String,
    pub machine_id: String,
    pub thread_id: String,
    pub deep_link: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<Phase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// `AgentActivityAlert` / `ApnsLiveActivityAlert`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub title: String,
    pub body: String,
}

/// The aggregate title. T3: "T3 Code"; the Vekrel app seeds its card with "Vekrel".
const TITLE: &str = "Vekrel";
pub const TERMINAL_AGENT_ACTIVITY_DISPLAY_TTL_MS: i64 = 15 * 60 * 1_000;
const RUNNING_AGENT_ACTIVITY_ROW_TTL_MS: i64 = 2 * 60 * 60 * 1_000;
const WAITING_AGENT_ACTIVITY_ROW_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
pub const TERMINAL_NOTIFICATION_FRESHNESS_MS: i64 = 2 * 60 * 1_000;
const MAX_SUMMARY_TEXT_LENGTH: usize = 120;
const MAX_STATUS_TEXT_LENGTH: usize = 40;
const MAX_DEEP_LINK_LENGTH: usize = 512;
pub const MAX_ACTIVITY_ROWS: usize = 5;

use crate::http::errors::{js_space, js_trim};

/// `truncateText`: lengths in UTF-16 units.
// shortcut: a cut inside a surrogate pair drops the lone half (JS keeps it, JSON then escapes it
// as `\udXXX`); titles would need an emoji exactly at unit 117 to differ.
fn truncate_text(value: &str, max: usize) -> String {
    let t = js_trim(value);
    if t.encode_utf16().count() <= max {
        return t.to_owned();
    }
    let mut out = String::new();
    let mut units = 0;
    for c in t.chars() {
        units += c.len_utf16();
        if units > max - 3 {
            break;
        }
        out.push(c);
    }
    format!("{}...", out.trim_end_matches(js_space))
}

fn sanitize_deep_link(value: &str) -> String {
    let t = js_trim(value);
    if !t.starts_with('/') || t.starts_with("//") {
        return "/".into();
    }
    truncate_text(t, MAX_DEEP_LINK_LENGTH)
}

pub fn status_for_phase(phase: Phase) -> &'static str {
    match phase {
        Phase::WaitingForApproval => "Approval",
        Phase::WaitingForInput => "Input",
        Phase::Completed => "Done",
        Phase::Failed => "Failed",
        Phase::Starting => "Connecting",
        Phase::Running => "Working",
        Phase::Stale => "Waiting",
    }
}

/// `agentActivityExpiresAt`; `None` is NaN.
pub fn expires_at(phase: Phase, updated_at: &str) -> Option<i64> {
    let ttl = match phase {
        Phase::Running | Phase::Starting => RUNNING_AGENT_ACTIVITY_ROW_TTL_MS,
        _ => WAITING_AGENT_ACTIVITY_ROW_TTL_MS,
    };
    parse_iso_ms(updated_at).map(|ms| ms + ttl)
}

pub fn is_expired(state: &ActivityState, now_ms: i64) -> bool {
    expires_at(state.phase, &state.updated_at).is_none_or(|e| now_ms > e)
}

pub fn sanitize_row(row: &AggregateRow) -> AggregateRow {
    AggregateRow {
        project_title: truncate_text(&row.project_title, MAX_SUMMARY_TEXT_LENGTH),
        thread_title: truncate_text(&row.thread_title, MAX_SUMMARY_TEXT_LENGTH),
        model_title: truncate_text(&row.model_title, MAX_SUMMARY_TEXT_LENGTH),
        status: truncate_text(&row.status, MAX_STATUS_TEXT_LENGTH),
        deep_link: sanitize_deep_link(&row.deep_link),
        ..row.clone()
    }
}

pub fn sanitize_aggregate(a: &Aggregate) -> Aggregate {
    Aggregate {
        title: truncate_text(&a.title, MAX_SUMMARY_TEXT_LENGTH),
        subtitle: truncate_text(&a.subtitle, MAX_SUMMARY_TEXT_LENGTH),
        activities: a
            .activities
            .iter()
            .take(MAX_ACTIVITY_ROWS)
            .map(sanitize_row)
            .collect(),
        ..a.clone()
    }
}

pub fn sanitize_notification(n: &Notification) -> Notification {
    Notification {
        title: truncate_text(&n.title, MAX_SUMMARY_TEXT_LENGTH),
        body: truncate_text(&n.body, MAX_SUMMARY_TEXT_LENGTH),
        deep_link: sanitize_deep_link(&n.deep_link),
        ..n.clone()
    }
}

pub fn notification_for_activity(row: &AggregateRow) -> Notification {
    let a = sanitize_row(row);
    sanitize_notification(&Notification {
        body: format!("{}: {}", a.status, a.project_title),
        title: a.thread_title,
        machine_id: a.machine_id,
        thread_id: a.thread_id,
        deep_link: a.deep_link,
        phase: Some(a.phase),
        updated_at: Some(a.updated_at),
    })
}

fn row_for_state(s: &ActivityState) -> AggregateRow {
    AggregateRow {
        machine_id: s.machine_id.clone(),
        thread_id: s.thread_id.clone(),
        project_title: s.project_title.clone(),
        thread_title: s.thread_title.clone(),
        model_title: s.model_title.clone(),
        phase: s.phase,
        status: status_for_phase(s.phase).into(),
        updated_at: s.updated_at.clone(),
        deep_link: s.deep_link.clone(),
    }
}

fn finished_subtitle(phase: Phase) -> String {
    if phase == Phase::Failed {
        "Agent work failed"
    } else {
        "Agent work completed"
    }
    .into()
}

fn is_recent_terminal(s: &ActivityState, now_ms: i64) -> bool {
    s.phase.is_terminal()
        && parse_iso_ms(&s.updated_at)
            .is_some_and(|t| now_ms - t <= TERMINAL_AGENT_ACTIVITY_DISPLAY_TTL_MS)
}

pub fn activity_phase_priority(phase: Phase) -> u8 {
    match phase {
        Phase::WaitingForApproval | Phase::WaitingForInput => 0,
        Phase::Failed => 1,
        Phase::Starting | Phase::Running => 2,
        _ => 3,
    }
}

/// Newest first (`b.updatedAt.localeCompare(a.updatedAt)`; ISO strings compare the same ordinally).
fn recent_terminal(states: &[ActivityState], now_ms: i64) -> Vec<&ActivityState> {
    let mut v: Vec<&ActivityState> = states
        .iter()
        .filter(|s| is_recent_terminal(s, now_ms))
        .collect();
    v.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    v
}

/// `makeAggregateState`.
pub fn make_aggregate(
    active_states: &[ActivityState],
    terminal_state: Option<&ActivityState>,
    now_ms: i64,
) -> Option<Aggregate> {
    let mut active: Vec<&ActivityState> = active_states
        .iter()
        .filter(|s| !s.phase.is_terminal() && !is_expired(s, now_ms))
        .collect();
    if active.is_empty() {
        if let Some(t) = terminal_state {
            return Some(sanitize_aggregate(&Aggregate {
                title: TITLE.into(),
                subtitle: finished_subtitle(t.phase),
                active_count: 0,
                updated_at: t.updated_at.clone(),
                activities: vec![row_for_state(t)],
            }));
        }
        let recent = recent_terminal(active_states, now_ms);
        let newest = recent.first()?;
        return Some(sanitize_aggregate(&Aggregate {
            title: TITLE.into(),
            subtitle: finished_subtitle(newest.phase),
            active_count: 0,
            updated_at: newest.updated_at.clone(),
            activities: recent
                .iter()
                .take(MAX_ACTIVITY_ROWS)
                .map(|s| row_for_state(s))
                .collect(),
        }));
    }
    let recent = recent_terminal(active_states, now_ms);
    let active_count = active.len() as i64;
    let mut latest = active[0];
    for s in active.iter().chain(recent.iter()) {
        if s.updated_at > latest.updated_at {
            latest = s;
        }
    }
    let updated_at = latest.updated_at.clone();
    active.sort_by_key(|s| activity_phase_priority(s.phase));
    let displayed = active
        .iter()
        .take(MAX_ACTIVITY_ROWS)
        .chain(recent.iter())
        .take(MAX_ACTIVITY_ROWS)
        .map(|s| row_for_state(s))
        .collect();
    Some(sanitize_aggregate(&Aggregate {
        title: TITLE.into(),
        subtitle: "Agent work in progress".into(),
        active_count,
        updated_at,
        activities: displayed,
    }))
}

// ---- alerts (agentActivityAlerts.ts) ----

pub fn is_fresh_terminal_notification(updated_at: &str, now_ms: i64) -> bool {
    parse_iso_ms(updated_at).is_some_and(|t| now_ms - t <= TERMINAL_NOTIFICATION_FRESHNESS_MS)
}

fn same_row(a: &AggregateRow, b: &AggregateRow) -> bool {
    a.machine_id == b.machine_id && a.thread_id == b.thread_id
}

fn previous_phase(prev: &Aggregate, row: &AggregateRow) -> Option<Phase> {
    prev.activities
        .iter()
        .find(|p| same_row(p, row))
        .map(|p| p.phase)
}

pub fn row_phases_changed(prev: &Aggregate, next: &Aggregate) -> bool {
    prev.activities.len() != next.activities.len()
        || next
            .activities
            .iter()
            .any(|r| previous_phase(prev, r) != Some(r.phase))
}

pub fn alert_allowed_for_phase(p: Option<&Preferences>, phase: Phase) -> bool {
    let Some(p) = p else { return true };
    match phase {
        Phase::WaitingForApproval => p.notify_on_approval,
        Phase::WaitingForInput => p.notify_on_input,
        Phase::Completed => p.notify_on_completion,
        Phase::Failed => p.notify_on_failure,
        _ => false,
    }
}

/// A missing baseline is a replay, not a transition that should buzz the phone.
pub fn attention_transition_rows<'a>(
    prev: Option<&Aggregate>,
    next: &'a Aggregate,
    prefs: Option<&Preferences>,
) -> Vec<&'a AggregateRow> {
    let Some(prev) = prev else { return vec![] };
    next.activities
        .iter()
        .filter(|r| {
            r.phase.is_attention()
                && !prev
                    .activities
                    .iter()
                    .any(|p| p.phase.is_attention() && same_row(p, r))
                && alert_allowed_for_phase(prefs, r.phase)
        })
        .collect()
}

fn newly_terminal_rows<'a>(
    prev: Option<&Aggregate>,
    next: &'a Aggregate,
    include_unobserved: bool,
) -> Vec<&'a AggregateRow> {
    let Some(prev) = prev else { return vec![] };
    next.activities
        .iter()
        .filter(|r| {
            if !r.phase.is_terminal() {
                return false;
            }
            let before = previous_phase(prev, r);
            (include_unobserved || before.is_some()) && !before.is_some_and(Phase::is_terminal)
        })
        .collect()
}

pub fn terminal_transition_rows<'a>(
    prev: Option<&Aggregate>,
    next: &'a Aggregate,
    prefs: Option<&Preferences>,
    now_ms: i64,
    include_unobserved: bool,
) -> Vec<&'a AggregateRow> {
    newly_terminal_rows(prev, next, include_unobserved)
        .into_iter()
        .filter(|r| {
            alert_allowed_for_phase(prefs, r.phase)
                && is_fresh_terminal_notification(&r.updated_at, now_ms)
        })
        .collect()
}

pub fn alert_for_activity_rows(rows: &[&AggregateRow]) -> Option<Alert> {
    let first = rows.first()?;
    if rows.len() == 1 {
        return Some(Alert {
            title: first.thread_title.clone(),
            body: format!("{}: {}", first.status, first.project_title),
        });
    }
    let what = if first.phase.is_attention() {
        "need attention"
    } else {
        "finished"
    };
    Some(Alert {
        title: format!("{} agents {what}", rows.len()),
        body: rows
            .iter()
            .map(|r| r.thread_title.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    })
}

pub fn alert_for_attention_transition(
    prev: Option<&Aggregate>,
    next: &Aggregate,
    prefs: Option<&Preferences>,
) -> Option<Alert> {
    alert_for_activity_rows(&attention_transition_rows(prev, next, prefs))
}

pub fn alert_for_newly_terminal(
    prev: Option<&Aggregate>,
    next: &Aggregate,
    prefs: Option<&Preferences>,
    now_ms: i64,
    include_unobserved: bool,
) -> Option<Alert> {
    alert_for_activity_rows(&terminal_transition_rows(
        prev,
        next,
        prefs,
        now_ms,
        include_unobserved,
    ))
}

pub fn alert_for_terminal_aggregate(
    aggregate: Option<&Aggregate>,
    prefs: Option<&Preferences>,
) -> Option<Alert> {
    let row = aggregate?.activities.first()?;
    if !row.phase.is_terminal() {
        return None;
    }
    alert_allowed_for_phase(prefs, row.phase)
        .then(|| alert_for_activity_rows(&[row]))
        .flatten()
}

pub fn should_alert_for_activity(
    phase: Phase,
    updated_at: &str,
    prefs: Option<&Preferences>,
    now_ms: i64,
) -> bool {
    prefs.is_some_and(|p| p.notifications_enabled)
        && alert_allowed_for_phase(prefs, phase)
        && (!phase.is_terminal() || is_fresh_terminal_notification(updated_at, now_ms))
}

// ---- Android data (fcmPayloads.ts, FcmDeliveries.ts) ----

fn clean(value: &str) -> String {
    let mut out = String::new();
    let mut in_space = false;
    for c in value.chars() {
        if js_space(c) {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    js_trim(&out).to_owned()
}

/// `androidActivityData`, in T3's key order.
pub fn android_activity_data(aggregate: Option<&Aggregate>) -> Map<String, Value> {
    let mut rows: Vec<&AggregateRow> = aggregate
        .map(|a| a.activities.iter().collect())
        .unwrap_or_default();
    rows.sort_by_key(|r| activity_phase_priority(r.phase));
    let active = aggregate.map_or(0, |a| a.active_count);
    let attention = rows
        .iter()
        .filter(|r| activity_phase_priority(r.phase) == 0)
        .count();
    let failed = rows.iter().any(|r| r.phase == Phase::Failed);
    let title = if active > 0 {
        let s = if active == 1 { "" } else { "s" };
        let attn = if attention > 0 {
            let s = if attention == 1 { "s" } else { "" };
            format!(" · {attention} need{s} attention")
        } else {
            String::new()
        };
        format!("{active} active agent{s}{attn}")
    } else if failed {
        "Agent work failed".into()
    } else {
        "Agent work completed".into()
    };
    // `Math.max(0, ...)`: one NaN makes the whole maximum NaN.
    let mut expires = Some(0i64);
    for r in &rows {
        let e = if r.phase.is_terminal() {
            parse_iso_ms(&r.updated_at).map(|t| t + TERMINAL_AGENT_ACTIVITY_DISPLAY_TTL_MS)
        } else {
            expires_at(r.phase, &r.updated_at)
        };
        expires = expires.zip(e).map(|(a, b)| a.max(b));
    }
    let hero = rows.first();
    let mut m = Map::new();
    let mut put = |k: &str, v: String| {
        m.insert(k.into(), Value::String(v));
    };
    put("active", (active > 0).to_string());
    put(
        "activity_chip",
        match (active > 0, attention > 0) {
            (true, true) => "Review",
            (true, false) => "Active",
            _ => "",
        }
        .into(),
    );
    put("activity_title", title);
    put(
        "activity_phase",
        hero.map_or(String::new(), |h| h.phase.as_str().into()),
    );
    put("activity_active_count", active.to_string());
    put("activity_attention_count", attention.to_string());
    put(
        "activity_body",
        hero.map_or(String::new(), |h| {
            format!(
                "{}: {} · {}",
                h.status,
                clean(&h.thread_title),
                clean(&h.project_title)
            )
        }),
    );
    for (i, r) in rows.iter().enumerate() {
        put(
            &format!("activity_line_{i}"),
            [
                r.status.clone(),
                clean(&r.thread_title),
                clean(&r.project_title),
            ]
            .join("\t"),
        );
    }
    put(
        "activity_path",
        hero.map_or("/".into(), |h| h.deep_link.clone()),
    );
    put(
        "activity_expires_at",
        expires.map_or("NaN".into(), |e| e.to_string()),
    );
    m
}

fn utf8_json_len(m: &Map<String, Value>) -> usize {
    serde_json::to_string(m).expect("strings serialize").len()
}

fn str_of(m: &Map<String, Value>, k: &str) -> String {
    m[k].as_str().unwrap_or_default().to_owned()
}

/// `fitFcmData`: keep Unicode, escaping and grouped alerts within FCM's 4 KB data budget.
pub fn fit_fcm_data(input: &Map<String, Value>) -> Map<String, Value> {
    let mut data = input.clone();
    let mut keys: Vec<String> = data
        .keys()
        .filter(|k| {
            k.ends_with("_body") || k.ends_with("_title") || k.starts_with("activity_line_")
        })
        .cloned()
        .collect();
    while utf8_json_len(&data) > 3800 {
        // In place and stable, as `Array.prototype.sort`.
        keys.sort_by_key(|k| std::cmp::Reverse(str_of(&data, k).len()));
        let Some(key) = keys.first().cloned() else {
            break;
        };
        let value = str_of(&data, &key);
        if value.encode_utf16().count() <= 8 {
            keys.remove(0);
            continue;
        }
        let mut parts: Vec<String> = if key.starts_with("activity_line_") {
            value.split('\t').map(str::to_owned).collect()
        } else {
            vec![value]
        };
        let part = if parts.len() == 3 {
            if parts[1].encode_utf16().count() > parts[2].encode_utf16().count() {
                1
            } else {
                2
            }
        } else {
            0
        };
        let chars: Vec<char> = parts[part].chars().collect();
        // Five characters would become four plus the ellipsis and never shrink.
        if chars.len() <= 5 {
            keys.remove(0);
            continue;
        }
        let kept: String = chars[..chars.len() * 4 / 5].iter().collect();
        parts[part] = format!("{}…", kept.trim_end_matches(js_space));
        data.insert(key, Value::String(parts.join("\t")));
    }
    data
}

fn json_ids(ids: &[&str]) -> String {
    serde_json::to_string(ids).expect("strings serialize")
}

fn single_alert(row: &AggregateRow) -> Map<String, Value> {
    let n = notification_for_activity(row);
    let mut m = Map::new();
    m.insert(
        "alert_id".into(),
        json_ids(&[
            &row.machine_id,
            &row.thread_id,
            row.phase.as_str(),
            &row.updated_at,
        ])
        .into(),
    );
    m.insert(
        "alert_group".into(),
        json_ids(&[&row.machine_id, &row.thread_id]).into(),
    );
    m.insert("alert_title".into(), n.title.into());
    m.insert("alert_body".into(), n.body.into());
    m.insert("alert_path".into(), n.deep_link.into());
    m
}

/// `androidAlertForState`.
pub fn android_alert_for_state(
    state: &ActivityState,
    prefs: &Preferences,
    now_ms: i64,
) -> Option<Map<String, Value>> {
    should_alert_for_activity(state.phase, &state.updated_at, Some(prefs), now_ms)
        .then(|| single_alert(&row_for_state(state)))
}

/// `androidAlertForAggregate`.
pub fn android_alert_for_aggregate(
    prev: &Aggregate,
    next: &Aggregate,
    prefs: &Preferences,
    now_ms: i64,
) -> Option<Map<String, Value>> {
    if !prefs.notifications_enabled {
        return None;
    }
    let attention = attention_transition_rows(Some(prev), next, Some(prefs));
    let rows = if attention.is_empty() {
        terminal_transition_rows(Some(prev), next, Some(prefs), now_ms, true)
    } else {
        attention
    };
    let alert = alert_for_activity_rows(&rows)?;
    if rows.len() == 1 {
        return Some(single_alert(rows[0]));
    }
    // shortcut: T3 sorts with `localeCompare`; ordinal order equals it for ASCII ids. The id is
    // only hashed for on-device dedupe, so a different order for exotic ids costs nothing more.
    let mut ids: Vec<String> = rows
        .iter()
        .map(|r| json_ids(&[&r.machine_id, &r.thread_id, r.phase.as_str(), &r.updated_at]))
        .collect();
    ids.sort();
    let mut m = Map::new();
    m.insert("alert_id".into(), format!("[{}]", ids.join(",")).into());
    m.insert("alert_title".into(), alert.title.into());
    m.insert("alert_body".into(), alert.body.into());
    // A multi-thread alert targets the overview.
    m.insert("alert_path".into(), "/".into());
    Some(m)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// T3's own outputs (`tests/fixtures/push/gen.ts`), with the Vekrel renames applied.
    pub fn vectors() -> Value {
        let raw = include_str!("../../tests/fixtures/push/t3-vectors.json")
            .replace("environmentId", "machineId")
            .replace("T3 Code", "Vekrel");
        serde_json::from_str(&raw).unwrap()
    }

    pub fn now(v: &Value) -> i64 {
        v["nowMs"].as_i64().unwrap()
    }

    fn states(v: &Value) -> Vec<ActivityState> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| serde_json::from_value(s.clone()).unwrap())
            .collect()
    }

    fn opt<T: serde::de::DeserializeOwned>(v: &Value) -> Option<T> {
        (!v.is_null()).then(|| serde_json::from_value(v.clone()).unwrap())
    }

    fn json<T: Serialize>(t: &T) -> String {
        serde_json::to_string(t).unwrap()
    }

    #[test]
    fn aggregates_equal_t3() {
        let v = vectors();
        let inputs = v["aggregateInputs"].as_object().unwrap();
        assert!(inputs.len() >= 8);
        for (k, input) in inputs {
            let terminal: Option<ActivityState> = opt(&input["terminalState"]);
            let got = make_aggregate(&states(&input["activeStates"]), terminal.as_ref(), now(&v));
            assert_eq!(json(&got), json(&v["aggregates"][k]), "{k}");
        }
    }

    #[test]
    fn notifications_equal_t3() {
        let v = vectors();
        for (k, n) in v["notifications"].as_object().unwrap() {
            let a: Aggregate = opt(&v["aggregates"][k]).unwrap();
            assert_eq!(
                json(&notification_for_activity(&a.activities[0])),
                json(n),
                "{k}"
            );
        }
    }

    #[test]
    fn alerts_equal_t3() {
        let v = vectors();
        let now = now(&v);
        for (k, t) in v["transitions"].as_object().unwrap() {
            let i = &t["input"];
            let prev: Option<Aggregate> = opt(&i["previousAggregate"]);
            let next: Aggregate = opt(&i["nextAggregate"]).unwrap();
            let prefs: Option<Preferences> = opt(&i["preferences"]);
            let (p, pr) = (prev.as_ref(), prefs.as_ref());
            assert_eq!(
                json(&alert_for_attention_transition(p, &next, pr)),
                json(&t["attention"]),
                "{k}"
            );
            assert_eq!(
                json(&alert_for_newly_terminal(p, &next, pr, now, true)),
                json(&t["newlyTerminal"]),
                "{k}"
            );
            assert_eq!(
                json(&alert_for_newly_terminal(p, &next, pr, now, false)),
                json(&t["newlyTerminalObservedOnly"]),
                "{k}"
            );
            let changed = p.map(|p| row_phases_changed(p, &next));
            assert_eq!(json(&changed), json(&t["rowPhasesChanged"]), "{k}");
            let android = p
                .zip(pr)
                .and_then(|(p, pr)| android_alert_for_aggregate(p, &next, pr, now));
            assert_eq!(json(&android), json(&t["androidAggregate"]), "{k}");
        }
        let allow = Preferences {
            live_activities_enabled: true,
            notifications_enabled: true,
            notify_on_approval: true,
            notify_on_input: true,
            notify_on_completion: true,
            notify_on_failure: true,
        };
        let mute = Preferences {
            notify_on_completion: false,
            notify_on_failure: false,
            ..allow
        };
        for (k, t) in v["terminalAlerts"].as_object().unwrap() {
            let a: Option<Aggregate> = opt(&v["aggregates"][k]);
            assert_eq!(
                json(&alert_for_terminal_aggregate(a.as_ref(), Some(&allow))),
                json(&t["allowed"]),
                "{k}"
            );
            assert_eq!(
                json(&alert_for_terminal_aggregate(a.as_ref(), Some(&mute))),
                json(&t["muted"]),
                "{k}"
            );
        }
        let quiet = Preferences {
            notifications_enabled: false,
            ..allow
        };
        for (k, t) in v["androidStates"].as_object().unwrap() {
            let s: ActivityState = opt(&v["states"][k]).unwrap();
            assert_eq!(
                json(&android_alert_for_state(&s, &allow, now)),
                json(&t["allowed"]),
                "{k}"
            );
            assert_eq!(
                json(&android_alert_for_state(&s, &quiet, now)),
                json(&t["muted"]),
                "{k}"
            );
        }
    }

    #[test]
    fn android_data_equals_t3() {
        use sha2::{Digest, Sha256};
        let v = vectors();
        let agg = |k: &str| -> Option<Aggregate> {
            match k {
                "huge" => opt(&v["huge"]),
                "empty" => None,
                k => opt(&v["aggregates"][k]),
            }
        };
        for (k, f) in v["fcm"].as_object().unwrap() {
            let raw = f["raw"].as_object().unwrap();
            let mut data = Map::new();
            for key in ["t3_kind", "device_id", "user_id", "updated_at"] {
                data.insert(key.into(), raw[key].clone());
            }
            data.extend(android_activity_data(agg(k).as_ref()));
            // The alert part comes from the vector (its builders are compared above); hash it as
            // `FcmDeliveries.process` does.
            for (key, val) in raw.iter().filter(|(k, _)| k.starts_with("alert_")) {
                data.insert(key.clone(), val.clone());
            }
            assert_eq!(json(&data), json(&raw), "{k}");
            assert_eq!(json(&fit_fcm_data(&data)), json(&f["fitted"]), "{k}");
            if let Some(Value::String(id)) = raw.get("alert_id") {
                assert_eq!(id.len(), 64);
                let _ = Sha256::digest(id.as_bytes());
            }
        }
        assert!(
            serde_json::to_string(&v["fcm"]["huge"]["raw"])
                .unwrap()
                .len()
                > 3800,
            "the huge case must exercise fitting"
        );
    }
}
