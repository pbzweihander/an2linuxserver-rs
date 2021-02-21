use structopt::StructOpt;

#[derive(StructOpt)]
pub struct Opt {
    #[structopt(subcommand)]
    pub cmd: Option<Subcommand>,
}

#[derive(StructOpt)]
pub enum Subcommand {
    Pair,
}
