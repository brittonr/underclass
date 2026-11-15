use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use underclass::claude::{ClaudeResetError, manual_reset};
use underclass::models::{Account, AccountStatus, BackendId, Surface};
use underclass::pool::PoolCore;
use underclass::store::Store;

struct Scenario {
    before: Value,
    after: Value,
    consume_body: String,
    consumed: usize,
    pause: bool,
    after_status: u16,
}

impl Scenario {
    fn new(body: Value) -> Self {
        Self {
            before: json!({
                "five_hour": {"utilization": 100, "resets_at": "2099-01-01T00:00:00Z"},
                "seven_day": {"utilization": 20}
            }),
            after: json!({"five_hour": {"utilization": 10}, "seven_day": {"utilization": 20}}),
            consume_body: body.to_string(),
            consumed: 0,
            pause: false,
            after_status: 200,
        }
    }
}

struct Upstream {
    scenario: Mutex<Scenario>,
    consume_started: tokio::sync::Notify,
    release_consume: tokio::sync::Notify,
}

async fn usage(State(upstream): State<Arc<Upstream>>) -> Response {
    let scenario = upstream.scenario.lock().unwrap();
    if scenario.consumed == 0 {
        Json(scenario.before.clone()).into_response()
    } else {
        (
            http::StatusCode::from_u16(scenario.after_status).unwrap(),
            Json(scenario.after.clone()),
        )
            .into_response()
    }
}

async fn credits() -> Json<Value> {
    Json(json!({"credits": [{
        "id": "synthetic-credit", "reset_type": "claude_rate_limits", "status": "available"
    }]}))
}

async fn consume(State(upstream): State<Arc<Upstream>>) -> Response {
    let (body, pause) = {
        let mut scenario = upstream.scenario.lock().unwrap();
        scenario.consumed += 1;
        (scenario.consume_body.clone(), scenario.pause)
    };
    if pause {
        upstream.consume_started.notify_one();
        upstream.release_consume.notified().await;
    }
    ([(http::header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn cooling_account() -> (Store, Arc<Mutex<PoolCore>>, Account) {
    let store = Store::in_memory().unwrap();
    let mut account =
        underclass::flows::new_account(BackendId::Claude, "owner@example.test".into());
    account.status = AccountStatus::Cooling;
    account.reset_at = i64::MAX;
    store.upsert_account(&account);
    let core = PoolCore::new(
        &store,
        HashMap::from([(BackendId::Claude, vec![Surface::Anthropic])]),
    );
    (store, Arc::new(Mutex::new(core)), account)
}

fn assert_status(
    store: &Store,
    pool: &Mutex<PoolCore>,
    account: &Account,
    expected: AccountStatus,
) {
    assert_eq!(store.get_account(&account.id).unwrap().status, expected);
    assert_eq!(
        pool.lock().unwrap().account(&account.id).unwrap().status,
        expected
    );
}

// One isolated integration-test process owns its environment override. Set it before creating
// runtime/client threads; every upstream request is directed to the loopback fixture.
#[test]
fn claude_reset_requires_explicit_success_and_current_shared_headroom() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    unsafe {
        std::env::set_var("UNDERCLASS_CLAUDE_UPSTREAM", format!("http://{address}"));
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let upstream = Arc::new(Upstream {
                scenario: Mutex::new(Scenario::new(json!({"code": "reset"}))),
                consume_started: tokio::sync::Notify::new(),
                release_consume: tokio::sync::Notify::new(),
            });
            let app = Router::new()
                .route("/api/oauth/usage", routing::get(usage))
                .route("/api/oauth/rate-limit-reset-credits", routing::get(credits))
                .route(
                    "/api/oauth/rate-limit-reset-credits/consume",
                    routing::post(consume),
                )
                .with_state(upstream.clone());
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let client = reqwest::Client::builder().no_proxy().build().unwrap();

            for (body, expected) in [
                (json!({"code": "no_credit"}), ClaudeResetError::NoCredit),
                (
                    json!({"code": "nothing_to_reset"}),
                    ClaudeResetError::NotRateLimited,
                ),
                (json!({}), ClaudeResetError::Upstream("consume outcome")),
                (
                    json!({"code": null}),
                    ClaudeResetError::Upstream("consume outcome"),
                ),
                (
                    json!({"code": false}),
                    ClaudeResetError::Upstream("consume outcome"),
                ),
                (
                    json!({"code": "unexpected"}),
                    ClaudeResetError::Upstream("consume outcome"),
                ),
            ] {
                *upstream.scenario.lock().unwrap() = Scenario::new(body);
                let (store, pool, account) = cooling_account();
                let result =
                    manual_reset(&client, &account, "synthetic", &pool, &store, false).await;
                assert_eq!(result.map(|outcome| outcome.status), Err(expected));
                assert_status(&store, &pool, &account, AccountStatus::Cooling);
                assert_eq!(store.get_account(&account.id).unwrap().reset_at, i64::MAX);
            }
            {
                let mut scenario = Scenario::new(json!({}));
                scenario.consume_body = "not-json".into();
                *upstream.scenario.lock().unwrap() = scenario;
                let (store, pool, account) = cooling_account();
                let result =
                    manual_reset(&client, &account, "synthetic", &pool, &store, false).await;
                assert_eq!(
                    result.map(|outcome| outcome.status),
                    Err(ClaudeResetError::Upstream("consume"))
                );
                assert_status(&store, &pool, &account, AccountStatus::Cooling);
            }
            for code in ["reset", "already_redeemed"] {
                *upstream.scenario.lock().unwrap() = Scenario::new(json!({"code": code}));
                let (store, pool, account) = cooling_account();
                let result = manual_reset(&client, &account, "synthetic", &pool, &store, false)
                    .await
                    .unwrap();
                assert_eq!(result.outcome, code);
                assert_eq!(result.status, AccountStatus::Healthy);
                assert_status(&store, &pool, &account, AccountStatus::Healthy);
                assert_eq!(upstream.scenario.lock().unwrap().consumed, 1);
            }
            // Shared headroom does not make a spent family window pointless to reset.
            {
                let mut scenario = Scenario::new(json!({"code": "reset"}));
                scenario.before["five_hour"]["utilization"] = json!(20);
                scenario.before["seven_day_fable"] = json!({
                    "utilization": 100, "resets_at": "2099-01-01T00:00:00Z"
                });
                *upstream.scenario.lock().unwrap() = scenario;
                let (store, pool, account) = cooling_account();
                {
                    let mut core = pool.lock().unwrap();
                    core.set_status(&account.id, AccountStatus::Healthy, 0);
                    store.update_account_status(&account.id, AccountStatus::Healthy, 0);
                    core.report_model_family_quota(&account.id, "claude-fable-", i64::MAX);
                }
                let result = manual_reset(&client, &account, "synthetic", &pool, &store, false)
                    .await
                    .unwrap();
                assert_eq!(result.status, AccountStatus::Healthy);
                assert_eq!(upstream.scenario.lock().unwrap().consumed, 1);
                assert!(
                    pool.lock()
                        .unwrap()
                        .select(
                            underclass::models::now_ms(),
                            None,
                            "claude-fable-5-1",
                            Surface::Anthropic
                        )
                        .is_ok()
                );
            }
            for after in [
                json!({"five_hour": {"utilization": "unknown"}, "seven_day": {"utilization": 20}}),
                json!({"five_hour": {"utilization": 20}, "seven_day": {"utilization": 100}}),
                json!({"seven_day_fable": {"utilization": 20}}),
                json!({"five_hour": null, "seven_day": null}),
            ] {
                let mut scenario = Scenario::new(json!({"code": "reset"}));
                scenario.after = after;
                *upstream.scenario.lock().unwrap() = scenario;
                let (store, pool, account) = cooling_account();
                let result = manual_reset(&client, &account, "synthetic", &pool, &store, false)
                    .await
                    .unwrap();
                assert_eq!(result.status, AccountStatus::Cooling);
                assert_status(&store, &pool, &account, AccountStatus::Cooling);
            }
            {
                let mut scenario = Scenario::new(json!({"code": "reset"}));
                scenario.after_status = 500;
                *upstream.scenario.lock().unwrap() = scenario;
                let (store, pool, account) = cooling_account();
                let result = manual_reset(&client, &account, "synthetic", &pool, &store, false)
                    .await
                    .unwrap();
                assert_eq!(result.status, AccountStatus::Cooling);
                assert_eq!(upstream.scenario.lock().unwrap().consumed, 1);
                assert_status(&store, &pool, &account, AccountStatus::Cooling);
            }
            // An operator action completes while the successful redemption is in flight.
            for status in [
                Some(AccountStatus::Disabled),
                Some(AccountStatus::AuthError),
                None,
            ] {
                let mut scenario = Scenario::new(json!({"code": "reset"}));
                scenario.pause = true;
                *upstream.scenario.lock().unwrap() = scenario;
                let (store, pool, account) = cooling_account();
                let reset = manual_reset(&client, &account, "synthetic", &pool, &store, false);
                let change_state = async {
                    upstream.consume_started.notified().await;
                    {
                        let mut core = pool.lock().unwrap();
                        if let Some(status) = status {
                            core.set_status(&account.id, status, 0);
                            store.update_account_status(&account.id, status, 0);
                        } else {
                            core.remove_account(&account.id);
                            store.delete_account(&account.id);
                        }
                    }
                    upstream.release_consume.notify_one();
                };
                let (result, ()) = tokio::join!(reset, change_state);
                if let Some(status) = status {
                    assert_eq!(result.unwrap().status, status);
                    assert_status(&store, &pool, &account, status);
                } else {
                    assert_eq!(
                        result.map(|outcome| outcome.status),
                        Err(ClaudeResetError::Upstream("account removed"))
                    );
                    assert!(store.get_account(&account.id).is_none());
                    assert!(pool.lock().unwrap().account(&account.id).is_none());
                }
            }
            // A fresh observation of an external reset restores Cooling without consuming a credit.
            {
                let mut scenario = Scenario::new(json!({"code": "reset"}));
                scenario.before = json!({"five_hour": null, "seven_day": {"utilization": 20}});
                *upstream.scenario.lock().unwrap() = scenario;
                let (store, pool, account) = cooling_account();
                let result =
                    manual_reset(&client, &account, "synthetic", &pool, &store, false).await;
                assert_eq!(
                    result.map(|outcome| outcome.status),
                    Err(ClaudeResetError::NotRateLimited)
                );
                assert_status(&store, &pool, &account, AccountStatus::Healthy);
                assert_eq!(upstream.scenario.lock().unwrap().consumed, 0);
            }
            server.abort();
        });
}
