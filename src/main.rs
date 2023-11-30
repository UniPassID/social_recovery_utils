use clap::{Parser, Subcommand};

pub mod utils;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    OpenID {
        #[arg(long, default_value = "false")]
        create: bool,
        #[arg(long, default_value = "openid.sk")]
        sk_path: String,
        #[arg(long, default_value = "default_kid")]
        kid: String,
        #[arg(long, default_value = "default_iss")]
        iss: String,
        #[arg(long, default_value = "default_sub")]
        sub: String,
        #[arg(long, default_value = "default_aud")]
        aud: String,
        #[arg(long, default_value = "default_nonce")]
        nonce: String,
    },
    Email {
        #[arg(long, default_value = "false")]
        create: bool,
        #[arg(long, default_value = "email.sk")]
        sk_path: String,
        #[arg(long, default_value = "Alice <alice@test.com>")]
        from: String,
        #[arg(long, default_value = "Bob <bob@test.com>")]
        to: String,
        #[arg(long, default_value = "test_subject")]
        subject: String,
        #[arg(long, default_value = "test_body")]
        body: String,
        #[arg(long, default_value = "test_selector")]
        selector: String,
        #[arg(long, default_value = "test_domain")]
        domain: String,
    },
    Passkey {
        #[arg(long)]
        challenge: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::OpenID {
            create,
            sk_path,
            kid,
            iss,
            sub,
            aud,
            nonce,
        } => {
            let res = openid_gen::generate_args(create, sk_path, kid, iss, sub, aud, nonce);
            println!("{}", res);
        }
        Commands::Email {
            create,
            sk_path,
            from,
            to,
            subject,
            body,
            selector,
            domain,
        } => {
            let res = email_gen::generate_args(
                create, sk_path, from, to, subject, body, selector, domain,
            );
            println!("{}", res);
        }
        Commands::Passkey { challenge } => {
            let res = passkey_gen::generate_args(challenge).await;
            println!("{}", res);
        }
    }
}
