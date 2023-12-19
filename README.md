# Social Recovery Utils
This repository is intended for generating mock data for the reference implementation of ERC-7093, specifically the [SocialRecoveryInterface](https://github.com/UniPassID/SocialRecoveryInterface).


## usage

Compile
```sh
cargo build --release
```
OpenID

```sh
./target/release/social_recovery_utils open-id -h
Usage: social_recovery_utils open-id [OPTIONS]

Options:
      --create             
      --sk-path <SK_PATH>  [default: openid.sk]
      --kid <KID>          [default: default_kid]
      --iss <ISS>          [default: default_iss]
      --sub <SUB>          [default: default_sub]
      --aud <AUD>          [default: default_aud]
      --nonce <NONCE>      [default: default_nonce]
  -h, --help               Print help
```
Email

```sh
./target/release/social_recovery_utils email -h  
Usage: social_recovery_utils email [OPTIONS]

Options:
      --create               
      --sk-path <SK_PATH>    [default: email.sk]
      --from <FROM>          [default: "Alice <alice@test.com>"]
      --to <TO>              [default: "Bob <bob@test.com>"]
      --subject <SUBJECT>    [default: test_subject]
      --body <BODY>          [default: test_body]
      --selector <SELECTOR>  [default: test_selector]
      --domain <DOMAIN>      [default: test_domain]
  -h, --help                 Print help
```

Passkey

```sh
./target/release/social_recovery_utils passkey -h
Usage: social_recovery_utils passkey --challenge <CHALLENGE>

Options:
      --challenge <CHALLENGE>  
  -h, --help                   Print help
```

License
-------
All smart contracts are released under LGPL-3.0