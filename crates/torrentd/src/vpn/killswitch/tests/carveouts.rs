//! The kill switch's carve-outs for a cluster ([`Carveouts`]): what they
//! render, what they let out and what they do not, and that the watch reads
//! them back as rendered.

use super::*;

/// A pod's carve-outs: the API (port 8080) replying by `eth0`, and the
/// cluster resolver, IPv4 and IPv6.
fn cluster() -> Carveouts {
    Carveouts::new(
        Some(8080),
        &["eth0".to_string()],
        &["10.43.0.10".parse().unwrap(), "fd00:43::a".parse().unwrap()],
    )
}

/// The carve-outs are the last accepts, ahead of the drop, one rule per
/// interface and per resolver and protocol, and nothing renders without
/// them.
#[test]
fn the_carve_outs_render_ahead_of_the_drop() {
    let rs =
        render_ruleset_with_transport(998, &cluster(), &[tunnel("wg-a")], &[transport_on(51820)])
            .unwrap();
    // The six lines before the chain's and the table's closing braces.
    let tail: Vec<&str> = rs.lines().map(str::trim).rev().skip(2).take(6).collect();
    assert_eq!(
        tail.into_iter().rev().collect::<Vec<_>>(),
        [
            "meta skuid 998 oifname \"eth0\" tcp sport 8080 accept",
            "meta skuid 998 ip daddr 10.43.0.10 udp dport 53 accept",
            "meta skuid 998 ip daddr 10.43.0.10 tcp dport 53 accept",
            "meta skuid 998 ip6 daddr fd00:43::a udp dport 53 accept",
            "meta skuid 998 ip6 daddr fd00:43::a tcp dport 53 accept",
            "meta skuid 998 counter drop",
        ],
        "{rs}"
    );
    let bare = render_ruleset_with_transport(
        998,
        &Carveouts::default(),
        &[tunnel("wg-a")],
        &[transport_on(51820)],
    )
    .unwrap();
    assert!(
        !bare.contains("eth0") && !bare.contains("dport 53"),
        "{bare}"
    );
    // No port, as for a unix listener: no API carve-out at all.
    let no_port = Carveouts::new(None, &["eth0".to_string()], &[]);
    assert_eq!(no_port, Carveouts::default());
    assert!(!no_port.dns_exempt() && cluster().dns_exempt());
}

/// What the carve-outs let out, and everything beside them they do not: the
/// API port by another interface, another port by the named one, a UDP
/// packet from the API port, port 53 to an unnamed address, another port to
/// the named resolver, and a tunnel's address by the named interface.
#[test]
fn the_carve_outs_let_out_what_they_name_and_nothing_else() {
    let rs =
        render_ruleset_with_transport(998, &cluster(), &[tunnel("wg-a")], &[transport_on(51820)])
            .unwrap();
    let pod = Ipv4Addr::new(10, 42, 0, 9);
    let probe = "10.42.0.1:51000";
    for (what, p, want) in [
        (
            "an API reply by eth0",
            pkt(998, pod, "eth0").tcp(8080, probe),
            "accept",
        ),
        (
            "an API reply by eth1",
            pkt(998, pod, "eth1").tcp(8080, probe),
            "drop",
        ),
        (
            "a peer connection by eth0",
            pkt(998, pod, "eth0").tcp(6881, probe),
            "drop",
        ),
        (
            "UDP from the API port",
            pkt(998, pod, "eth0").udp(8080, probe),
            "drop",
        ),
        (
            "DNS over UDP",
            pkt(998, pod, "eth0").udp(40000, "10.43.0.10:53"),
            "accept",
        ),
        (
            "DNS over TCP",
            pkt(998, pod, "eth0").tcp(40000, "10.43.0.10:53"),
            "accept",
        ),
        (
            "DNS over IPv6",
            pkt(998, "fd00:42::9".parse::<IpAddr>().unwrap(), "eth0").udp(40000, "[fd00:43::a]:53"),
            "accept",
        ),
        (
            "DNS to another resolver",
            pkt(998, pod, "eth0").udp(40000, "8.8.8.8:53"),
            "drop",
        ),
        (
            "another port to the resolver",
            pkt(998, pod, "eth0").udp(40000, "10.43.0.10:5353"),
            "drop",
        ),
        (
            "the tunnel address by eth0",
            pkt(998, ADDR_A, "eth0").tcp(8080, probe),
            "drop",
        ),
        (
            "another uid's packet",
            pkt(1000, pod, "eth0").tcp(6881, probe),
            "accept",
        ),
    ] {
        assert_eq!(verdict(&rs, p), want, "{what}");
    }
}

/// The carve-outs' rules read back from nft's listing as rendered, so the
/// watch does not take a table carrying them for a drifted one.
#[test]
fn a_table_with_carve_outs_verifies_intact() {
    let rule = |handle: u32, exprs: &str| {
        format!(
            r#"{{"rule": {{"family": "inet", "table": "torrentd_ks_998", "chain": "output", "handle": {handle}, "expr": [{{"match": {{"op": "==", "left": {{"meta": {{"key": "skuid"}}}}, "right": 998}}}}, {exprs}, {{"accept": null}}]}}}}"#
        )
    };
    let m = |left: &str, right: &str| {
        format!(r#"{{"match": {{"op": "==", "left": {left}, "right": {right}}}}}"#)
    };
    let payload = |proto: &str, field: &str| {
        format!(r#"{{"payload": {{"protocol": "{proto}", "field": "{field}"}}}}"#)
    };
    let oif = r#"{"meta": {"key": "oifname"}}"#;
    let api = rule(
        10,
        &format!(
            "{}, {}",
            m(oif, r#""eth0""#),
            m(&payload("tcp", "sport"), "8080")
        ),
    );
    let dns = |handle: u32, family: &str, server: &str, proto: &str| {
        rule(
            handle,
            &format!(
                "{}, {}",
                m(&payload(family, "daddr"), &format!(r#""{server}""#)),
                m(&payload(proto, "dport"), "53"),
            ),
        )
    };
    let entries = [
        dns(11, "ip", "10.43.0.10", "udp"),
        dns(12, "ip", "10.43.0.10", "tcp"),
        dns(13, "ip6", "fd00:43::a", "udp"),
        dns(14, "ip6", "fd00:43::a", "tcp"),
    ];
    let installed = Installed::render(
        998,
        cluster(),
        vec![tunnel("wg-a")],
        vec![("wg-a".to_string(), two_peer_transport())],
    )
    .unwrap();
    let json = listing(&[
        META,
        FENCE,
        LO,
        WG_A,
        PORT_V4,
        PORT_V6,
        &api,
        &entries[0],
        &entries[1],
        &entries[2],
        &entries[3],
        DROP,
    ]);
    let verdict = verify_with(
        &installed,
        || Ok(format!("table inet {TABLE}\n")),
        move || Ok(json.clone()),
    )
    .unwrap();
    assert_eq!(verdict, Verdict::Intact);
}

/// The carve-outs are fixed for the run: the install renders them, and a
/// reinstall over a changed transport keeps them.
#[test]
fn enable_renders_the_carve_outs_and_a_refresh_keeps_them() {
    let applied = std::cell::RefCell::new(Vec::<String>::new());
    let mut installed = enable_for_uid(
        998,
        &cluster(),
        &["wg-a".to_string()],
        addr_of,
        no_v6,
        |_| Ok(transport_on(51820)),
        |script| {
            applied.borrow_mut().push(script.to_string());
            Ok(())
        },
    )
    .unwrap();
    let moved = Transport::new(45136, [ENDPOINT.parse().unwrap()]);
    assert!(refresh(
        &mut installed,
        addr_of,
        unchanged_v6,
        reads(&[("wg-a", Ok(moved))]),
        |script| {
            applied.borrow_mut().push(script.to_string());
            Ok(())
        },
    ));
    let applied = applied.borrow();
    assert_eq!(applied.len(), 2);
    for script in applied.iter() {
        assert!(
            script.contains("meta skuid 998 oifname \"eth0\" tcp sport 8080 accept")
                && script.contains("meta skuid 998 ip daddr 10.43.0.10 udp dport 53 accept"),
            "{script}"
        );
    }
}

/// An API interface the ruleset cannot quote is refused before `nft`.
#[test]
fn an_unquotable_api_interface_is_refused() {
    let bad = Carveouts::new(Some(8080), &["eth0\" accept".to_string()], &[]);
    let e = render_ruleset_with_transport(998, &bad, &[tunnel("wg-a")], &[]).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    assert!(e.to_string().contains("kill_switch_api_interfaces"), "{e}");
}
