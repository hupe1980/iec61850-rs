//! An IED that **subscribes** to a GOOSE stream and publishes what it thinks of it.
//!
//! This is the seam between the two buses inside one device. A GOOSE subscriber already knows
//! whether its stream is alive, which `confRev` is arriving and whether the publisher is
//! asking to be commissioned; IEC 61850-7-4 gives that a home in an `LGOS` logical node, one
//! per subscription, so a SCADA client can read it and a report control block can carry it.
//!
//! Everything here runs in one process with no network interface: a publisher feeds a
//! subscriber directly, the subscriber's status goes into the model, and a client on a
//! loopback socket reads it back.
//!
//! ```text
//! cargo run --example supervised_subscriber
//! ```

use iec61850_rs::client::Client;
use iec61850_rs::common::{Instant, TimeQuality, UtcTime};
use iec61850_rs::model::IedModel;
use iec61850_rs::proto::data::{Typed, Value};
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, FrameHeader, MacAddr};
use iec61850_rs::proto::goose::{GoosePdu, PublisherConfig, Subscriber, SubscriberConfig, SubscriptionKey};
use iec61850_rs::server::{Ied, Server, SubscriptionStatus};
use iec61850_rs::{Fc, Result};

/// The subscribing IED: one `LGOS`, engineered to watch `IED1`'s trip GOOSE.
const SUBSCRIBER: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="sub"/>
  <IED name="IED2"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
    <LN lnClass="LGOS" inst="1" prefix="" lnType="LGOS_T">
      <DOI name="GoCBRef"><DAI name="setSrcRef"><Val>IED1LD0/LLN0$GO$gcbTrip</Val></DAI></DOI>
    </LN>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="LGOS_T" lnClass="LGOS">
      <DO name="St" type="SPS_T"/>
      <DO name="NdsCom" type="SPS_T"/>
      <DO name="LastStNum" type="INS_T"/>
      <DO name="RxConfRevNum" type="INS_T"/>
      <DO name="GoCBRef" type="ORG_T"/>
    </LNodeType>
    <DOType id="SPS_T" cdc="SPS">
      <DA name="stVal" fc="ST" bType="BOOLEAN"/><DA name="q" fc="ST" bType="Quality"/><DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>
    <DOType id="INS_T" cdc="INS">
      <DA name="stVal" fc="ST" bType="INT32"/><DA name="q" fc="ST" bType="Quality"/><DA name="t" fc="ST" bType="Timestamp"/>
    </DOType>
    <DOType id="ORG_T" cdc="ORG"><DA name="setSrcRef" fc="SP" bType="ObjRef"/></DOType>
  </DataTypeTemplates>
</SCL>"#;

/// The publisher this IED watches — an ordinary GOOSE control block on another device.
const GOCB: &str = "IED1LD0/LLN0$GO$gcbTrip";

fn main() -> Result<()> {
    // Which logical node supervises which control block is **engineering**, so it comes out
    // of the file rather than being typed here a second time.
    let model = IedModel::from_scl(SUBSCRIBER, None)?;
    let node = model.supervision().into_iter().find(|n| n.watches(GOCB)).ok_or(iec61850_rs::Error::NotFound("an LGOS for that control block"))?;
    println!("{} supervises {}", node.node, node.control_block.as_deref().unwrap_or("-"));

    let server = Server::bind("127.0.0.1:0", Ied::new(model)?)?;
    let addr = server.local_addr()?.to_string();
    let updates = server.handle();
    std::thread::spawn(move || {
        let _ = server.accept_one();
    });

    // The process-bus half. Nothing touches a socket: the publisher's frames go straight into
    // the subscriber, which is what makes this runnable anywhere.
    let key = SubscriptionKey { dst: MacAddr::GOOSE_BASE, appid: 1, gocb_ref: GOCB.into() };
    let mut subscriber = Subscriber::new(SubscriberConfig::new(key).with_conf_rev(3));
    let publisher = PublisherConfig::new(link(), GOCB, "IED1LD0/LLN0$dsTrip").with_conf_rev(3);

    let mut client = Client::connect(&addr)?;
    println!("before anything arrives: St = {:?}", read_bool(&mut client, "IED2LD0/LGOS1.St.stVal"));

    // Three retransmissions of one state, as a publisher on the bus would send them.
    for sq_num in 0..3 {
        subscriber.on_frame(Instant::ZERO.plus_millis(sq_num), &frame(&publisher, 7, sq_num as u32)?);
    }
    updates.txn().supervise(&node.node, &SubscriptionStatus::from_goose(&subscriber)).commit();
    println!(
        "stream up:  St = {:?}, LastStNum = {:?}, RxConfRevNum = {:?}",
        read_bool(&mut client, "IED2LD0/LGOS1.St.stVal"),
        read_int(&mut client, "IED2LD0/LGOS1.LastStNum.stVal"),
        read_int(&mut client, "IED2LD0/LGOS1.RxConfRevNum.stVal"),
    );

    // The publisher goes quiet for longer than the `timeAllowedtoLive` it advertised. That is
    // the alarm an operator sees, and it is now an ordinary part of the model.
    subscriber.on_timeout(Instant::ZERO.plus_millis(60_000));
    updates.txn().supervise(&node.node, &SubscriptionStatus::from_goose(&subscriber)).commit();
    println!("stream lost: St = {:?}", read_bool(&mut client, "IED2LD0/LGOS1.St.stVal"));

    client.release()?;
    Ok(())
}

fn link() -> FrameHeader {
    FrameHeader { dst: MacAddr::GOOSE_BASE, src: MacAddr([2, 0, 0, 0, 0, 1]), vlan: None, ethertype: ETHERTYPE_GOOSE, appid: 1, reserved1: 0, reserved2: 0 }
}

/// One frame of the supervised stream.
fn frame(cfg: &PublisherConfig, st_num: u32, sq_num: u32) -> Result<Vec<u8>> {
    let pdu = GoosePdu {
        gocb_ref: cfg.gocb_ref.clone(),
        time_allowed_to_live: cfg.retransmission.tal_after(sq_num),
        dat_set: cfg.dat_set.clone(),
        go_id: None,
        t: UtcTime::from_unix(1_700_000_000, 0, TimeQuality::SYNCHRONIZED),
        st_num,
        sq_num,
        simulation: false,
        conf_rev: cfg.conf_rev,
        nds_com: false,
        all_data: vec![Value::Boolean(true)],
    };
    cfg.header.to_frame(&pdu.encode()?)
}

fn read_bool(c: &mut Client, reference: &str) -> Option<bool> {
    c.read(reference, Fc::ST).ok().and_then(|v| v.as_bool())
}

fn read_int(c: &mut Client, reference: &str) -> Option<i64> {
    c.read(reference, Fc::ST).ok().and_then(|v| v.as_i64())
}
