use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const AF_INET_RAW: u16 = 2;
pub const AF_INET6_RAW: u16 = 10;

pub fn net_addr_from_raw(family: u16, addr: [u8; 16]) -> Option<IpAddr> {
    match family {
        AF_INET_RAW => Some(IpAddr::V4(Ipv4Addr::new(
            addr[12], addr[13], addr[14], addr[15],
        ))),
        AF_INET6_RAW => Some(IpAddr::V6(Ipv6Addr::from(addr))),
        _ => None,
    }
}

pub fn raw_net_addr(ip: IpAddr) -> (u16, [u8; 16]) {
    match ip {
        IpAddr::V4(ip) => {
            let mut addr = [0; 16];
            addr[12..16].copy_from_slice(&ip.octets());
            (AF_INET_RAW, addr)
        }
        IpAddr::V6(ip) => (AF_INET6_RAW, ip.octets()),
    }
}
