//! No-op policy reasoner
//! This reasoner does a little as possible and functions as base for other implementations of the
//! policy reasoner.
use std::env;
use std::fs::File;
use std::net::SocketAddr;

pub mod implementation;

use clap::Parser;
use humanlog::{DebugMode, HumanLogger};
use implementation::no_op::NoOpReasonerConnector;
use log::{info};
use policy_reasoner::auth::{JwtConfig, JwtResolver, KidResolver};
use policy_reasoner::logger::FileLogger;
use policy_reasoner::sqlite::SqlitePolicyDataStore;
use reasonerconn::ReasonerConnector;
use srv::Srv;
use state_resolver::StateResolver;

/***** HELPER FUNCTIONS *****/
fn get_pauth_resolver() -> policy_reasoner::auth::JwtResolver<KidResolver> {
    let kid_resolver = KidResolver::new("./examples/config/jwk_set_expert.json").unwrap();
    let r = File::open("./examples/config/jwt_resolver.yaml").unwrap();
    let jwt_cfg: JwtConfig = serde_yaml::from_reader(r).unwrap();
    JwtResolver::new(jwt_cfg, kid_resolver).unwrap()
}
fn get_dauth_resolver() -> policy_reasoner::auth::JwtResolver<KidResolver> {
    let kid_resolver = KidResolver::new("./examples/config/jwk_set_delib.json").unwrap();
    let r = File::open("./examples/config/jwt_resolver.yaml").unwrap();
    let jwt_cfg: JwtConfig = serde_yaml::from_reader(r).unwrap();
    JwtResolver::new(jwt_cfg, kid_resolver).unwrap()
}

/***** ARGUMENTS *****/
/// Defines the arguments for the `policy-reasoner` server.
#[derive(Debug, Parser, Clone)]
struct Arguments {
    /// Whether to enable full debugging
    #[clap(long, global = true, help = "If given, enables more verbose debugging.")]
    trace: bool,

    /// The address on which to bind ourselves.
    #[clap(short, long, env, default_value = "127.0.0.1:3030", help = "The address on which to bind the server.")]
    address: SocketAddr,
}

/***** PLUGINS *****/
/// The plugin used to do the audit logging.
type AuditLogPlugin = FileLogger;

/// The plugin used to do authentication for the policy expert API.
type PolicyAuthResolverPlugin = JwtResolver<KidResolver>;
/// The plugin used to do authentication for the deliberation API.
type DeliberationAuthResolverPlugin = JwtResolver<KidResolver>;

/// The plugin used to interact with the policy store.
type PolicyStorePlugin = SqlitePolicyDataStore;

type StateResolverPlugin = NoStateResolver;

struct NoStateResolver;

#[async_trait::async_trait]
impl StateResolver for NoStateResolver {
    type Error = std::convert::Infallible;

    async fn get_state(&self, _use_case: String) -> Result<state_resolver::State, Self::Error> {
        // Simply return a clone of the internal one
        panic!("Get state called on a reasoner without state");
    }
}

/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() {
    let args: Arguments = Arguments::parse();

    let rconn = NoOpReasonerConnector::new();

    // Setup a logger
    if let Err(err) = HumanLogger::terminal(if args.trace { DebugMode::Full } else { DebugMode::Debug }).init() {
        eprintln!("WARNING: Failed to setup logger: {err} (no logging for this session)");
    }

    info!("{} - v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    run_app(args, rconn).await;
}

async fn run_app<R>(args: Arguments, rconn: R)
where
    R: ReasonerConnector<AuditLogPlugin> + Send + Sync + 'static,
{
    // Initialize the plugins
    let log_identifier = format!("{binary} v{version}", binary = env!("CARGO_BIN_NAME"), version = env!("CARGO_PKG_VERSION"));
    let logger: AuditLogPlugin = FileLogger::new(log_identifier, "./audit-log.log");
    let pauthresolver: PolicyAuthResolverPlugin = get_pauth_resolver();
    let dauthresolver: DeliberationAuthResolverPlugin = get_dauth_resolver();
    let pstore: PolicyStorePlugin = SqlitePolicyDataStore::new("./data/policy.db");

    let sresolve = StateResolverPlugin {};

    // Run them!
    let server = Srv::new(args.address, logger, rconn, pstore, sresolve, pauthresolver, dauthresolver);

    server.run().await;
}
