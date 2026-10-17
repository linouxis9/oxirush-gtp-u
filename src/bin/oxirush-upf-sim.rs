//! A test UPF with one manually provisioned session, for local N3 tests.

use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;

use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};

const USAGE: &str = "usage: oxirush-upf-sim <bind-ip:port> <gnb-ip:port> <uplink-teid> \
                     <downlink-teid> [qfi] [--tun <name> <ue-ipv4>]
TEIDs are decimal, or hexadecimal after 0x.";

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
            [name, ue_address] => (
                &args[..at],
                Some((name.clone(), argument("UE address", ue_address)?)),
            ),
            _ => return Err("--tun takes an interface name and a UE IPv4 address".into()),
        },
        None => (args, None),
    };
    let (bind, gnb_address, uplink_teid, downlink_teid, qfi) = match positional {
        [bind, gnb, uplink, downlink] => (bind, gnb, uplink, downlink, 9),
        [bind, gnb, uplink, downlink, qfi] => (bind, gnb, uplink, downlink, argument("QFI", qfi)?),
        _ => return Err("wrong number of arguments".into()),
    };
    Ok(Args {
        bind: argument("bind address", bind)?,
        session: Session::new(
            teid("uplink TEID", uplink_teid)?,
            teid("downlink TEID", downlink_teid)?,
            argument("gNB address", gnb_address)?,
            qfi,
        ),
        tun,
    })
}

/// Argument `what`, which `text` gives.
fn argument<T: std::str::FromStr>(what: &str, text: &str) -> Result<T, Box<dyn Error>>
where
    T::Err: std::fmt::Display,
{
    text.parse()
        .map_err(|error| format!("{what} {text:?}: {error}").into())
}

/// A TEID, decimal or hexadecimal after `0x`.
fn teid(what: &str, text: &str) -> Result<u32, Box<dyn Error>> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(digits) => u32::from_str_radix(digits, 16),
        None => text.parse(),
    };
    parsed.map_err(|error| format!("{what} {text:?}: {error}").into())
}

async fn serve(args: Args) -> Result<(), Box<dyn Error>> {
    let (upf, mut packets) = UpfSimulator::bind(args.bind).await?;
    let session = args.session;
    upf.set_session(session)?;
    if let Some((name, ue_address)) = args.tun {
        attach_tun(&upf, session.uplink_teid, name, ue_address)?;
    }
    println!(
        "UPF simulator on {}: uplink TEID {:#010x}, downlink TEID {:#010x} at gNB {}",
        upf.local_addr()?,
        session.uplink_teid,
        session.downlink_teid,
        session.gnb_address
    );
    let stopped = shutdown_signal();
    tokio::pin!(stopped);
    loop {
        let packet = tokio::select! {
            result = &mut stopped => {
                result?;
                break;
            }
            packet = packets.recv() => match packet {
                Some(packet) => packet,
                None => break,
            },
        };
        println!(
            "uplink TEID {:#010x} from {}: {} octets",
            packet.uplink_teid,
            packet.from,
            packet.packet.payload.len()
        );
    }
    upf.shutdown().await?;
    Ok(())
}

async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &str) -> Result<Args, String> {
        let args: Vec<String> = args.split(' ').map(String::from).collect();
        parse(&args).map_err(|error| error.to_string())
    }

    #[test]
    fn teids_are_decimal_or_hexadecimal() {
        let args = parsed("127.0.0.8:2152 127.0.0.1:2152 0x1001 4097 5").unwrap();
        assert_eq!(args.session.uplink_teid, 0x1001);
        assert_eq!(args.session.downlink_teid, 0x1001);
        assert_eq!(args.session.qfi, 5);
        assert_eq!(args.bind, "127.0.0.8:2152".parse().unwrap());
    }

    #[test]
    fn an_argument_that_does_not_parse_is_named() {
        let cases = [
            (
                "127.0.0.8:2152 127.0.0.1:2152 0x10g1 1",
                "uplink TEID \"0x10g1\": invalid digit found in string",
            ),
            (
                "127.0.0.8:2152 127.0.0.1:2152 1 x",
                "downlink TEID \"x\": invalid digit found in string",
            ),
            (
                "127.0.0.8 127.0.0.1:2152 1 2",
                "bind address \"127.0.0.8\": invalid socket address syntax",
            ),
            (
                "127.0.0.8:2152 127.0.0.1:2152 1 2 300",
                "QFI \"300\": number too large to fit in target type",
            ),
            (
                "127.0.0.8:2152 127.0.0.1:2152 1 2 --tun oxupf0 10.45.0",
                "UE address \"10.45.0\": invalid IPv4 address syntax",
            ),
        ];
        for (args, error) in cases {
            assert_eq!(parsed(args).err().as_deref(), Some(error), "{args}");
        }
    }
}
