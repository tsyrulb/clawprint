//! Demo: Generate a synthetic Clawprint recording
//!
//! This example creates a realistic-looking recording without needing
//! a live OpenClaw gateway. Use it to explore the CLI and web dashboard.
//!
//! Usage:
//!   cargo run --example demo
//!
//! Then try:
//!   clawprint list   --out ./clawprints
//!   clawprint stats  --run <run_id> --out ./clawprints
//!   clawprint verify --run <run_id> --out ./clawprints
//!   clawprint view   --run <run_id> --out ./clawprints --open
//!   clawprint replay --run <run_id> --out ./clawprints --offline

use clawprint::storage::RunStorage;
use clawprint::{Event, EventId, EventKind, RunId, RunMeta};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let out_dir = PathBuf::from("./clawprints");
    let run_id = RunId::new();
    let short_id = &run_id.0[..8];

    println!("Creating demo recording: {}", run_id.0);
    println!("Output directory: ./clawprints\n");

    let mut storage = RunStorage::new(run_id.clone(), &out_dir, 50)?;

    let agent_run_id_1 = uuid::Uuid::new_v4().to_string();
    let agent_run_id_2 = uuid::Uuid::new_v4().to_string();

    let mut seq: u64 = 1;

    // --- RUN_START ---
    let event = Event::new(
        run_id.clone(),
        EventId(seq),
        EventKind::RunStart,
        serde_json::json!({
            "gateway_url": "ws://127.0.0.1:18789",
            "conn_id": uuid::Uuid::new_v4().to_string(),
        }),
        None,
    );
    storage.write_event(event)?;
    seq += 1;

    // --- Agent Run 1: User asks to read and summarise a file ---
    let agent1_events = vec![
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_1,
                "stream": "lifecycle",
                "type": "start",
                "prompt": "Read the file src/main.rs and summarise what it does."
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_1,
                "stream": "assistant",
                "type": "tool_use",
                "tool": "read_file",
                "args": {"path": "src/main.rs"}
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_1,
                "stream": "assistant",
                "type": "tool_result",
                "tool": "read_file",
                "result": "fn main() {\n    println!(\"Hello, world!\");\n}\n"
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_1,
                "stream": "assistant",
                "type": "text",
                "content": "The file contains a simple Rust main function that prints \"Hello, world!\" to stdout."
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_1,
                "stream": "lifecycle",
                "type": "end",
                "exitCode": 0
            }
        })),
    ];

    for (gw_event, payload) in &agent1_events {
        let kind = match *gw_event {
            "agent" => EventKind::AgentEvent,
            "chat" => EventKind::OutputChunk,
            _ => EventKind::Custom,
        };
        let event = Event::new(run_id.clone(), EventId(seq), kind, payload.clone(), None);
        storage.write_event(event)?;
        seq += 1;
    }

    // --- Some ticks and presence ---
    for _ in 0..5 {
        let event = Event::new(
            run_id.clone(),
            EventId(seq),
            EventKind::Tick,
            serde_json::json!({"gateway_event": "tick", "data": {"ts": chrono::Utc::now()}}),
            None,
        );
        storage.write_event(event)?;
        seq += 1;
    }

    let event = Event::new(
        run_id.clone(),
        EventId(seq),
        EventKind::Presence,
        serde_json::json!({
            "gateway_event": "presence",
            "data": {"agents": [{"agentId": "main", "status": "idle"}]}
        }),
        None,
    );
    storage.write_event(event)?;
    seq += 1;

    // --- Agent Run 2: User asks to write a test ---
    let agent2_events = vec![
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_2,
                "stream": "lifecycle",
                "type": "start",
                "prompt": "Write a unit test for the greeting function."
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_2,
                "stream": "assistant",
                "type": "tool_use",
                "tool": "read_file",
                "args": {"path": "src/lib.rs"}
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_2,
                "stream": "assistant",
                "type": "tool_result",
                "tool": "read_file",
                "result": "pub fn greet(name: &str) -> String {\n    format!(\"Hello, {}!\", name)\n}\n"
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_2,
                "stream": "assistant",
                "type": "tool_use",
                "tool": "write_file",
                "args": {
                    "path": "tests/test_greet.rs",
                    "content": "#[test]\nfn test_greet() {\n    assert_eq!(greet(\"World\"), \"Hello, World!\");\n}\n"
                }
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_2,
                "stream": "assistant",
                "type": "tool_result",
                "tool": "write_file",
                "result": "OK"
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_2,
                "stream": "assistant",
                "type": "tool_use",
                "tool": "bash",
                "args": {"command": "cargo test"}
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_2,
                "stream": "assistant",
                "type": "tool_result",
                "tool": "bash",
                "result": "running 1 test\ntest test_greet ... ok\n\ntest result: ok. 1 passed; 0 failed"
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_2,
                "stream": "assistant",
                "type": "text",
                "content": "I've created the test file and verified it passes. The test covers the basic greeting functionality."
            }
        })),
        ("agent", serde_json::json!({
            "gateway_event": "agent",
            "data": {
                "runId": agent_run_id_2,
                "stream": "lifecycle",
                "type": "end",
                "exitCode": 0
            }
        })),
    ];

    for (gw_event, payload) in &agent2_events {
        let kind = match *gw_event {
            "agent" => EventKind::AgentEvent,
            "chat" => EventKind::OutputChunk,
            _ => EventKind::Custom,
        };
        let event = Event::new(run_id.clone(), EventId(seq), kind, payload.clone(), None);
        storage.write_event(event)?;
        seq += 1;
    }

    // --- Chat output chunks ---
    let chat_chunks = vec![
        serde_json::json!({
            "gateway_event": "chat",
            "data": {"runId": agent_run_id_2, "delta": "I've created "}
        }),
        serde_json::json!({
            "gateway_event": "chat",
            "data": {"runId": agent_run_id_2, "delta": "the test file and "}
        }),
        serde_json::json!({
            "gateway_event": "chat",
            "data": {"runId": agent_run_id_2, "delta": "verified it passes."}
        }),
        serde_json::json!({
            "gateway_event": "chat",
            "data": {
                "runId": agent_run_id_2,
                "state": "final",
                "text": "I've created the test file and verified it passes. The test covers the basic greeting functionality."
            }
        }),
    ];

    for payload in &chat_chunks {
        let event = Event::new(
            run_id.clone(),
            EventId(seq),
            EventKind::OutputChunk,
            payload.clone(),
            None,
        );
        storage.write_event(event)?;
        seq += 1;
    }

    // --- More ticks ---
    for _ in 0..3 {
        let event = Event::new(
            run_id.clone(),
            EventId(seq),
            EventKind::Tick,
            serde_json::json!({"gateway_event": "tick", "data": {"ts": chrono::Utc::now()}}),
            None,
        );
        storage.write_event(event)?;
        seq += 1;
    }

    // --- Custom event (presence update) ---
    let event = Event::new(
        run_id.clone(),
        EventId(seq),
        EventKind::Custom,
        serde_json::json!({
            "gateway_event": "status",
            "data": {"agents": [{"agentId": "main", "status": "idle"}], "version": "3.1.0"}
        }),
        None,
    );
    storage.write_event(event)?;
    seq += 1;

    // --- RUN_END ---
    let event = Event::new(
        run_id.clone(),
        EventId(seq),
        EventKind::RunEnd,
        serde_json::json!({
            "conn_id": uuid::Uuid::new_v4().to_string(),
            "total_events": seq,
        }),
        None,
    );
    storage.write_event(event)?;

    // Flush and finalize
    storage.flush()?;

    let root_hash = storage.root_hash().unwrap_or_default();
    let meta = RunMeta {
        run_id: run_id.clone(),
        started_at: chrono::Utc::now() - chrono::Duration::minutes(12),
        ended_at: Some(chrono::Utc::now()),
        event_count: storage.event_count(),
        root_hash,
        gateway_url: "ws://127.0.0.1:18789".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    storage.finalize(&meta)?;

    let total = storage.event_count();

    println!("Demo recording created successfully!\n");
    println!("  Run ID:  {}", run_id.0);
    println!("  Events:  {}", total);
    println!("  Agents:  2 conversation runs");
    println!("  Path:    ./clawprints/runs/{}/\n", run_id.0);
    println!("Try these commands:\n");
    println!("  clawprint list   --out ./clawprints");
    println!("  clawprint stats  --run {} --out ./clawprints", short_id);
    println!("  clawprint verify --run {} --out ./clawprints", short_id);
    println!("  clawprint replay --run {} --out ./clawprints --offline", short_id);
    println!("  clawprint view   --run {} --out ./clawprints --open", run_id.0);

    Ok(())
}
