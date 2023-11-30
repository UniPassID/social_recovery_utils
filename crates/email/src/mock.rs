use lettre::{
    message::{
        header::{ContentType, HeaderName},
        DkimCanonicalization, DkimCanonicalizationType, DkimConfig, DkimSigningKey,
    },
    Message,
};

pub fn construct_email(
    from: String,
    to: String,
    subject: String,
    body: String,
    selector: String,
    domain: String,
    signing_key: DkimSigningKey,
) -> Vec<u8> {
    let mut message = Message::builder()
        .from(from.parse().unwrap())
        .to(to.parse().unwrap())
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .unwrap();

    let dkim_config = DkimConfig::new(
        selector,
        domain,
        signing_key,
        vec![
            HeaderName::new_from_ascii_str("From"),
            HeaderName::new_from_ascii_str("Subject"),
            HeaderName::new_from_ascii_str("To"),
            HeaderName::new_from_ascii_str("Date"),
        ],
        DkimCanonicalization {
            header: DkimCanonicalizationType::Relaxed,
            body: DkimCanonicalizationType::Relaxed,
        },
    );

    message.sign(&dkim_config);

    message.formatted()
}
