use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    AF_INET_RAW, AF_INET6_RAW, ContentFragEvent, EventHeader, FdDupEvent, FileOpenEvent,
    FileRenameEvent, FileUnlinkEvent, MetaDropEvent, NetConnectEvent, ProcChdirEvent,
    ProcExecEvent, ProcExitEvent, ProcForkEvent, TlsAssocEvent, net_addr_from_raw, raw_net_addr,
};

#[test]
fn raw_net_addr_round_trips_ipv4_and_ipv6_layouts() {
    let ipv4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let (family, addr) = raw_net_addr(ipv4);
    assert_eq!(family, AF_INET_RAW);
    assert_eq!(&addr[..12], &[0; 12]);
    assert_eq!(net_addr_from_raw(family, addr), Some(ipv4));

    let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let (family, addr) = raw_net_addr(ipv6);
    assert_eq!(family, AF_INET6_RAW);
    assert_eq!(net_addr_from_raw(family, addr), Some(ipv6));
    assert_eq!(net_addr_from_raw(0, addr), None);
}

#[test]
fn wire_event_sizes_are_pinned_to_bpf_abi() {
    assert_eq!(size_of::<EventHeader>(), 88);
    assert_eq!(size_of::<ProcForkEvent>(), 104);
    assert_eq!(size_of::<ProcExecEvent>(), 608);
    assert_eq!(size_of::<ProcExitEvent>(), 96);
    assert_eq!(size_of::<ProcChdirEvent>(), 356);
    assert_eq!(size_of::<FdDupEvent>(), 104);
    assert_eq!(size_of::<FileOpenEvent>(), 380);
    assert_eq!(size_of::<FileUnlinkEvent>(), 360);
    assert_eq!(size_of::<FileRenameEvent>(), 624);
    assert_eq!(size_of::<NetConnectEvent>(), 137);
    assert_eq!(size_of::<ContentFragEvent>(), 3192);
    assert_eq!(size_of::<TlsAssocEvent>(), 112);
    assert_eq!(size_of::<MetaDropEvent>(), 120);
}
