//! csp0924's IEC 61850 crates as an interop peer: their client against a server, or their
//! server for a client. Prints one `OK|FAIL|SKIP <step>[: detail]` line per step and exits
//! non-zero if a step failed.
//!
//!     probe client <host> <port> <ld>
//!     probe server <port> <model.icd> <ied>

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iec61850_client::rcb::{RcbHandle, RcbWriteMask, TriggerOptions};
use iec61850_client::{ClientReport, IedConnection, ReportCallback};
use iec61850_mms::mms::client::MmsClientBuilder;
use iec61850_model::{ControlModel, MmsValue, FC};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok(step: &str, detail: impl std::fmt::Display) {
    println!("OK {step}: {detail}");
}
fn fail(step: &str, e: impl std::fmt::Display) {
    FAILED.fetch_add(1, Ordering::SeqCst);
    println!("FAIL {step}: {e}");
}
fn skip(step: &str, why: &str) {
    println!("SKIP {step}: {why}");
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("client") if args.len() >= 5 => client(&args[2], args[3].parse().expect("port"), &args[4]).await,
        Some("server") if args.len() >= 5 => server(args[2].parse().expect("port"), &args[3], &args[4]).await,
        _ => {
            eprintln!("usage: probe client <host> <port> <ld> | server <port> <model.icd> <ied>");
            std::process::exit(2);
        }
    }
    std::process::exit(i32::from(FAILED.load(Ordering::SeqCst) > 0));
}

async fn client(host: &str, port: u16, ld: &str) {
    let mms = MmsClientBuilder::new().connect_timeout_ms(5_000).request_timeout_ms(5_000).build();
    let conn = IedConnection::with_mms_client(mms);
    if let Err(e) = conn.connect(host, port).await {
        return fail("associate", e);
    }
    ok("associate", format!("{host}:{port}"));

    match conn.get_server_directory(false).await {
        Ok(lds) if lds.iter().any(|d| d == ld) => ok("directory", format!("{} logical devices", lds.len())),
        Ok(lds) => fail("directory", format!("{ld} missing from {lds:?}")),
        Err(e) => fail("directory", e),
    }
    match conn.get_logical_device_directory(ld).await {
        Ok(names) => ok("model", format!("{} logical nodes", names.len())),
        Err(e) => fail("model", e),
    }
    match conn.read_object(&format!("{ld}/MMXU1.TotW.mag.f"), FC::Mx).await {
        Ok(v) => ok("read", format!("{v:?}")),
        Err(e) => fail("read", e),
    }

    let rcb_ref = format!("{ld}/LLN0$RP$urcb");
    let reports = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&reports);
    let cb: ReportCallback = Arc::new(move |_r: Arc<ClientReport>| {
        seen.fetch_add(1, Ordering::SeqCst);
    });
    let enabled = async {
        conn.install_report_handler(None, &rcb_ref, None, cb).await?;
        let mut rcb = RcbHandle::new(&rcb_ref)?;
        rcb.set_trg_ops(TriggerOptions::DATA_CHANGED | TriggerOptions::GI);
        conn.set_rcb_values(&rcb, RcbWriteMask::TRG_OPS, false).await?;
        ok("write", "TrgOps");
        let mut rcb = RcbHandle::new(&rcb_ref)?;
        rcb.set_rpt_ena(true);
        conn.set_rcb_values(&rcb, RcbWriteMask::RPT_ENA, false).await?;
        let mut rcb = RcbHandle::new(&rcb_ref)?;
        rcb.set_gi(true);
        conn.set_rcb_values(&rcb, RcbWriteMask::GI, false).await?;
        Ok::<_, iec61850_client::ClientError>(())
    };
    match enabled.await {
        Ok(()) => {
            let dispatcher = conn.spawn_report_dispatcher(Duration::from_millis(50));
            for _ in 0..100 {
                if reports.load(Ordering::SeqCst) > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            dispatcher.abort();
            match reports.load(Ordering::SeqCst) {
                0 => fail("report", "no report within 10 s of a general interrogation"),
                n => ok("report", format!("{n} report(s)")),
            }
        }
        Err(e) => fail("report", e),
    }

    match conn.create_control_object(&format!("{ld}/CSWI1.Pos"), ControlModel::DirectNormal) {
        Ok(control) => match control.operate(MmsValue::BitString { padding: 6, data: vec![0b1000_0000] }).await {
            Ok(outcome) => ok("control-direct", format!("{outcome:?}")),
            Err(e) => fail("control-direct", e),
        },
        Err(e) => fail("control-direct", e),
    }
    skip("control-sbo", "the served model engineers one direct-normal object only");

    let _ = conn.disconnect().await;
    ok("release", "");
}

async fn server(port: u16, model: &str, ied: &str) {
    let xml = std::fs::read_to_string(model).expect("read the model");
    let built = iec61850_scl::parse_scl(&xml)
        .map_err(|e| e.to_string())
        .and_then(|raw| iec61850_scl::ResolvedScl::from_raw(raw).map_err(|e| e.to_string()))
        .and_then(|resolved| resolved.build_model(ied).map_err(|e| e.to_string()));
    let model = match built {
        Ok(m) => m,
        Err(e) => {
            fail("model", e);
            return;
        }
    };
    let server = iec61850_server::IedServer::builder()
        .model(Arc::new(model))
        .bind(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
        .build()
        .expect("build the server");
    let _handle = server.start().await.expect("start the server");
    println!("READY {port}");
    std::future::pending::<()>().await;
}
