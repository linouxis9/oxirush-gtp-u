//! A test UPF with one manually provisioned session, for local N3 tests.

use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;

use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};

const USAGE: &str = "usage: oxirush-upf-sim <bind-ip:port> <gnb-ip:port> <uplink-teid> \
                     <downlink-teid> [qfi] [--tun <name> <ue-ipv4>]";

struct Args {
    bind: SocketAddr,
    session: Session,
    tun: Option<(String, Ipv4Addr)>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let args = match parse(&args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("oxirush-upf-sim: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Box::<dyn Error>::from)
        .and_then(|runtime| runtime.block_on(serve(args)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("oxirush-upf-sim: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse(args: &[String]) -> Result<Args, Box<dyn Error>> {
    let (positional, tun) = match args.iter().position(|arg| arg == "--tun") {
        Some(at) => match &args[at + 1..] {
            [name, ue_address] => (&args[..at], Some((name.clone(), ue_address.parse()?))),
            _ => return Err("--tun takes an interface name and a UE IPv4 address".into()),
        },
        None => (args, None),
    };
    let (bind, gnb_address, uplink_teid, downlink_teid, qfi) = match positional {
        [bind, gnb, uplink, downlink] => (bind, gnb, uplink, downlink, 9),
        [bind, gnb, uplink, downlink, qfi] => (bind, gnb, uplink, downlink, qfi.parse()?),
        _ => return Err("wrong number of arguments".into()),
    };
    if qfi > 63 {
        return Err(format!("QFI {qfi} is outside 0..=63").into());
    }
    Ok(Args {
        bind: bind.parse()?,
        session: Session::new(
            uplink_teid.parse()?,
            downlink_teid.parse()?,
            gnb_address.parse()?,
            qfi,
        ),
        tun,
    })
}

async fn serve(args: Args) -> Result<(), Box<dyn Error>> {
    let (upf, mut packets) = UpfSimulator::bind(args.bind).await?;
    let session = args.session;
    upf.set_session(session);
    if let Some((name, ue_address)) = args.tun {
        attach_tun(&upf, session.uplink_teid, name, ue_address)?;
    }
    println!(
        "UPF simulator on {}: uplink TEID {}, downlink TEID {} at gNB {}",
        upf.local_addr()?,
        session.uplink_teid,
        session.downlink_teid,
        session.gnb_address
    );
    while let Some(packet) = packets.recv().await {
        println!(
            "uplink TEID {} from {}: {} bytes",
            packet.uplink_teid,
            packet.from,
            packet.packet.payload.len()
        );
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "tun"))]
fn attach_tun(
    upf: &UpfSimulator,
    uplink_teid: u32,
    name: String,
    ue_address: Ipv4Addr,
) -> io::Result<()> {
    use oxirush_gtp_u::tun::{Routing, TunConfig};
    upf.attach_tun(
        uplink_teid,
        TunConfig::new(name, Routing::Upf { ue_address }),
    )
}

#[cfg(not(all(target_os = "linux", feature = "tun")))]
fn attach_tun(_: &UpfSimulator, _: u32, _: String, _: Ipv4Addr) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "--tun needs Linux and the tun feature",
    ))
}
