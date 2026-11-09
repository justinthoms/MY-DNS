# Anycast DNS with FRR (iBGP, OSPF, IS-IS)

ISP NetControl can take part in an anycast DNS setup: several servers answer
on the same IP addresses, and your routers send each subscriber to the
nearest healthy one. NetControl does not speak BGP, OSPF or IS-IS itself.
It controls **one interface** that holds the anycast addresses, and FRR
(or any routing daemon) announces whatever is on that interface.

```
            ┌──────────── health check every few seconds ───────────┐
            │  DNS listening?  upstream answers <check name>?        │
            ▼                                                         │
  ISP NetControl ── N failures ──▶ ip link set anycast0 down ──▶ FRR withdraws the /32s
                 ◀─ M successes ── ip link set anycast0 up   ──▶ FRR announces them again
```

Because the decision is just "interface up or down", it works the same with
iBGP, eBGP, OSPF and IS-IS.

## 1. Put the anycast addresses on their own interface

Use a dummy interface, never the uplink. NetControl refuses the interface
that carries the default route.

```bash
sudo ip link add anycast0 type dummy && sudo ip link set anycast0 up
```

```bash
sudo ip addr add 103.160.195.230/32 dev anycast0
```

To make it permanent with netplan (`/etc/netplan/60-anycast.yaml`):

```yaml
network:
  version: 2
  dummy-devices:
    anycast0:
      addresses: [103.160.195.230/32, 103.199.160.80/32]
```

## 2. Announce the interface's addresses with FRR

Pick the block for your routing protocol (`sudo vtysh`, then `configure terminal`).

### iBGP (or eBGP)

```
ip prefix-list ANYCAST-DNS seq 10 permit 103.160.195.230/32
ip prefix-list ANYCAST-DNS seq 20 permit 103.199.160.80/32
!
route-map ANYCAST-OUT permit 10
 match ip address prefix-list ANYCAST-DNS
!
router bgp 65010
 neighbor 10.10.0.1 remote-as 65010
 address-family ipv4 unicast
  redistribute connected route-map ANYCAST-OUT
  neighbor 10.10.0.1 route-map ANYCAST-OUT out
 exit-address-family
```

`network 103.160.195.230/32` statements work too: FRR only advertises a
`network` when the route exists, and it disappears when anycast0 goes down.

### OSPF

```
interface anycast0
 ip ospf area 0.0.0.0
 ip ospf passive
!
router ospf
 ospf router-id 10.10.0.5
```

### IS-IS

```
interface anycast0
 ip router isis CORE
 isis passive
!
router isis CORE
 net 49.0001.0100.1000.0005.00
```

## 3. Turn it on in ISP NetControl, carefully

1. **DNS settings → Listen on**: make sure DNS listens on the anycast
   addresses ("All addresses", or select `anycast0`).
2. **Anycast**: choose `anycast0`, keep **Monitor only** ticked, enable, Save.
   Watch the page for a day. It shows each check and whether Auto mode
   *would* withdraw the routes.
3. Untick **Monitor only** and Save. From now on, **Auto** mode withdraws the
   routes after *N* failed checks in a row (default 3 × 5 s) and announces
   them after *M* successful ones (default 3).

**Maintenance (withdraw)** takes this server out of the anycast group on
purpose, for example before upgrading or rebooting. Switch back to **Auto**
afterwards. **Force announce** ignores the health checks.

When ISP NetControl stops (upgrade, `docker compose down`), it withdraws the
routes first, so subscribers move to the other servers. On start it
announces them again after the recovery threshold.

## 4. Check it

```bash
vtysh -c "show ip bgp neighbors 10.10.0.1 advertised-routes"
```

```bash
vtysh -c "show ip ospf database" ; vtysh -c "show isis database detail"
```

Every withdraw and announce is written to the **Audit log** (`anycast.withdrawn`,
`anycast.announced`) and listed on the Anycast page.

## Things to know

- **What the health check tests:** that DNS is listening and that an
  upstream resolver answers the health-check name (cache bypassed). If your
  upstreams fail on *every* anycast server at once, all of them withdraw.
  Use upstreams that are independent per site, or keep one site on Force announce.
- **If the ISP NetControl process is killed** (not stopped cleanly), it
  cannot withdraw. Docker restarts it within seconds, and the health checks
  resume.
- **Turning the feature off**, or switching to Monitor only, brings the
  interface back up if ISP NetControl had taken it down.
- Uninstalling leaves the interface as it is. If it is down, bring it up with
  `sudo ip link set anycast0 up`.
