use crate::crypto;
use crate::engine::Engine;
use crate::types::DrawRequest;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

type S = Arc<Engine>;

pub fn router(engine: S) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/pools", get(pools))
        .route("/v1/settlements", get(settlements))
        .route("/v1/entity/:did/risk", get(risk))
        .route("/v1/entity/:did/receipt", get(receipt))
        .route("/v1/draw", post(draw))
        .route("/v1/stream", get(stream))
        .layer(CorsLayer::permissive())
        .with_state(engine)
}

async fn health() -> impl IntoResponse { Json(serde_json::json!({ "status": "ok", "ts": crypto::now() })) }
async fn pools(State(e): State<S>) -> impl IntoResponse { Json(e.store.pools().await) }
async fn settlements(State(e): State<S>) -> impl IntoResponse { Json(e.store.settlements().await) }

async fn risk(State(e): State<S>, Path(did): Path<String>) -> impl IntoResponse {
    match e.store.risk(&did).await {
        Some(r) => Json(serde_json::to_value(r).unwrap()).into_response(),
        None => Json(serde_json::json!({ "error": "no risk state" })).into_response(),
    }
}

async fn receipt(State(e): State<S>, Path(did): Path<String>) -> impl IntoResponse {
    let r = e.store.db.read().await.receipts.get(&did).cloned();
    Json(serde_json::to_value(r).unwrap())
}

async fn draw(State(e): State<S>, Json(req): Json<DrawRequest>) -> impl IntoResponse {
    match e.draw(req).await {
        Ok(s) => Json(serde_json::to_value(s).unwrap()).into_response(),
        Err(err) => Json(serde_json::json!({ "error": err })).into_response(),
    }
}

async fn stream(State(e): State<S>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, e))
}

async fn handle_socket(mut socket: WebSocket, e: S) {
    let mut rx = e.events.subscribe();
    while let Ok(msg) = rx.recv().await {
        if socket.send(Message::Text(msg.to_string())).await.is_err() { break; }
    }
}
