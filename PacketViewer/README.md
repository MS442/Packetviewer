# IPv4 / IPv6 Packet Viewer + Fuzzy Fake-IP Detector

Android app (Java + XML) in two sections:

- **CN (Computer Networks):** RFC 791 / RFC 8200 header viewer, and an IPv6 transition-mechanisms tool
  (dual-stack, tunneling, translation) built on bitwise header parsing and the One's Complement checksum.
- **IS2 (Intelligent Systems):** a **Mamdani fuzzy inference system** that scores how likely an IP address
  is fake, with SQLite history of the results.

Mobile App Development topics used throughout: ViewPager2 + TabLayout (nested), CardView, SQLite
persistence with a schema upgrade, custom listeners.

## How to open in Android Studio

**Build environment requirements:** This project targets **Android Gradle Plugin (AGP) 9.0.1**, paired with **Gradle 9.1.0** via a pinned Gradle wrapper (`gradle/wrapper/gradle-wrapper.properties`) — this is the exact version combination Google's own AGP 9.0 release notes list as the tested default pairing.

**Important — do NOT accept Gradle version-upgrade prompts.** Android Studio will sometimes show a banner like *"New Minor Gradle Version Available"* during sync. Declining/dismissing it is intentional here: jumping Gradle forward (e.g. to 9.7.x) without also bumping AGP reintroduces a known internal crash (`Cannot mutate the dependencies of configuration ... after the configuration was resolved`, thrown from AGP's `ConstraintHandler`) — Gradle's stricter configuration-locking in newer point releases breaks older AGP internals even within the same "9.x" line. If you want a newer Gradle, the AGP version needs to move in lockstep with it (check each AGP release's official compatibility table on developer.android.com first).

1. Open Android Studio → **Open** → select the `PacketViewer` folder (this project root).
2. Let Gradle sync — Android Studio should honor the pinned `gradle-wrapper.properties` and download Gradle 9.1.0 automatically. If a version-upgrade prompt appears, dismiss it.
3. Let Gradle pull `androidx.appcompat`, `material`, `viewpager2`,
   `cardview`, `constraintlayout`, `recyclerview` from Maven Central / Google's repo.
4. Add your app icons (`ic_launcher`, `ic_launcher_round`) via
   **File → New → Image Asset** if you don't already have `mipmap` icons — the manifest
   references them but they aren't included here.
5. Run on an emulator or device (minSdk 24 / Android 7.0+).

*Note: this wrapper works for Android Studio's built-in Gradle sync. If you also want to run builds from a terminal via `./gradlew`, open Android Studio's Terminal tab once and run `gradle wrapper --gradle-version 9.1.0` to generate the missing launcher scripts and jar.*

## App structure: two sections, five screens

The top tabs switch between the two sections; each section has its own tabs.

| Section | Screen | Class | What it does |
|---|---|---|---|
| **CN** (Computer Networks) | **Viewer** | `cn/ViewerFragment` | Tap any field in the RFC 791 (IPv4) or RFC 8200 (IPv6) header grid to see an explanation. |
| **CN** | **Subnet** | `cn/SubnetFragment` | CIDR calculator for IPv4 and IPv6: network, broadcast, host range, split into equal subnets, VLSM. |
| **CN** | **Transition** | `cn/TransitionFragment` | NAT64 translation, 6in4 / DS-Lite tunnelling and dual-stack, run on real packets with latency and throughput computed from your inputs and from costs measured on the phone. |
| **IS2** (Intelligent Systems) | **Detector** | `is2/DetectorFragment` | Step 0 subnetting, then the duplicate check per subnet, then a **Mamdani fuzzy inference system** that scores how likely an address is fake (made up, spoofed, or not a valid host address). |
| **IS2** | **History** | `is2/HistoryFragment` | Every analysed address with its verdict, from SQLite. **Long-press an entry** to remove it; the Clear button wipes everything. |

---

# CN section

## Viewer

Interactive grids for the IPv4 (RFC 791) and IPv6 (RFC 8200) headers. Tapping a field shows its
width, meaning and typical values in the inspector card.

## Subnet: CIDR calculator

Type `192.168.1.77/26`, `10.0.0.9 255.255.0.0` or `2001:db8::1/48`. The screen shows mask, wildcard,
network, broadcast, host range and counts (IPv4 /31 follows RFC 3021, /32 is a host route; IPv6 has no
broadcast and the all-zero host is the subnet-router anycast address). **Split** divides a subnet into
equal parts; **VLSM** takes lines like `Sales 100` and allocates largest-first, each block aligned to its
own size, reporting when the parent block runs out. Maths: `cn/utils/SubnetCalculator` (BigInteger, so
IPv4 and IPv6 share the code). The IS2 detector calls the same class.

## Transition: translation, tunnelling, dual-stack

Nothing in this screen is a canned output. Every address and number is an input field (the defaults
are only starting values), and the report is produced by running real bytes through the engine in
`cn/net`:

| Mechanism | What actually happens |
|---|---|
| **NAT64 / DNS64** | The server's IPv4 address is embedded in the NAT64 prefix (RFC 6052, all six prefix lengths, u-octet rule, Well-Known Prefix only for global IPv4). ICMP echo, a TCP SYN/SYN-ACK and UDP are built with valid checksums, translated v6->v4 (RFC 7915) through a **stateful binding table** (RFC 6146: port allocation, timeouts, address-dependent filtering) and translated back. TCP/UDP checksums are updated **incrementally (RFC 1624)**, ICMP is recomputed with / without the pseudo-header. Output packets are re-parsed and their checksums verified. Unsupported or unsafe packets are **dropped with a reason** (hop limit 1, unsolicited inbound, outside the prefix, corrupt checksum, too big for the IPv4 MTU). |
| **6in4 / DS-Lite 4in6** | Real encapsulation (protocol 41 / next header 4), inner TTL / hop limit decremented once, tunnel MTU enforced, decapsulation checks the outer header and the configured peer (anti-spoofing). |
| **Dual-stack** | RFC 6724 destination ordering using the real policy table (longest prefix match), then an RFC 8305 Happy Eyeballs race computed from the two RTTs you enter and the "IPv6 black-holed" switch (250 ms attempt delay). |
| **Compare** | All mechanisms side by side on the same link. |

**Latency and throughput** (`cn/net/PathModel`):

- RTT = path RTT + extra RTT to the translator / tunnel end + 2 x measured per-packet processing.
- MSS = MTU - IP header - 20 (minus the tunnel header); wire bytes include 38 B of Ethernet framing.
- Goodput = min(link rate x MSS / wire bytes, window / RTT, Mathis 1.22 x MSS / (RTT x sqrt(loss)), CPU limit).
- Transfer time = handshake + slow-start rounds + remaining bytes / goodput.
- `cn/net/Benchmark` times the **real translate / encapsulate / decapsulate calls on this phone**
  (median of batches after a warm-up, logging switched off) and feeds them in, so the CPU figures
  change with the device. The honest result is that processing costs microseconds, so the latency
  penalty comes from the detour and header overhead, and the translator only becomes a throughput
  limit on a fast link.

Not simulated: IPv4 fragmentation / reassembly, ICMP error translation, TCP state tracking in NAT64,
the DS-Lite AFTR's NAT44 (its CPU cost is not included), and the network itself (RTT and loss are your
inputs, not measured over the internet).

---

# IS2 section

## Detector: Mamdani fuzzy fake-IP detector

**Step 0 (before anything else): subnetting.** The prefix box takes `26`, `/26` or a mask; blank means
/24 (IPv4) or /64 (IPv6), and `192.168.1.77/26` typed in the address box works too. The subnet is
found with the CN `SubnetCalculator`; the duplicate check then runs **per subnet** (same address under
a different prefix is a different entry), a network or broadcast address given to a host pushes the
Range score up to at least 85, and the report ends with the other addresses already analysed in that
subnet.

An IP address string alone cannot prove that an address is fake, so the detector scores
**suspicion** from three independent pieces of evidence and combines them with fuzzy rules:

```
Address (+ optional hex packet, + scenario)
   -> three crisp inputs (0-100)
   -> FUZZIFICATION -> RULE EVALUATION (min) -> AGGREGATION (max) -> CENTROID
   -> Suspicion score 0-100 + verdict
```

### 1. Inputs

| Input | Class | Meaning of 0 / 100 |
|---|---|---|
| **Range** | `analysis/RangeClassifier` | 0 = ordinary public block; 100 = block that can never be a normal host address. Uses the RFC 6890 special-purpose registry: private, shared (CGNAT), loopback, link-local, documentation, benchmarking, multicast, broadcast, Class E, IPv4-mapped, unallocated IPv6 space... |
| **Pattern** | `analysis/PatternAnalyzer` | 0 = digits look assigned; 100 = obviously hand-typed (`1.2.3.4`, `111.111.111.111`, `1234:5678:9abc...`, `dead:beef`). |
| **Header** | `analysis/HeaderForensics` | 0 = consistent (or no packet supplied); 100 = forged. Cross-checks the optional hex bytes: checksum, TTL / hop limit, source = destination (LAND), illegal source address, DF+MF, version, address entered vs header. |

**Scenario toggle.** The same private address is normal on a LAN but a classic "bogon" (spoofing
indicator) as a source on the public Internet, so the user picks *Public Internet* or *Local
network (LAN)*. This only changes the Range score of private / unique-local / link-local
addresses (for example 192.168.1.50: Range 50 on the Internet, 0 on a LAN).

### 2. Membership functions

| Variable | Sets (shape) |
|---|---|
| Range | ROUTABLE (trapezoid 0,0,10,35), LIMITED (triangle 20,45,70), RESERVED (trapezoid 55,80,100,100) |
| Pattern | NATURAL (trapezoid 0,0,15,40), PATTERNED (triangle 25,50,75), ARTIFICIAL (trapezoid 60,80,100,100) |
| Header | CONSISTENT (trapezoid 0,0,10,30), SUSPECT (triangle 15,40,65), FORGED (trapezoid 50,75,100,100) |
| **Suspicion** (output) | GENUINE (trapezoid 0,0,15,35), QUESTIONABLE (triangle 20,40,60), SUSPICIOUS (triangle 45,65,85), LIKELY_FAKE (trapezoid 70,88,100,100) |

### 3. Rule base: all 27 combinations (3 x 3 x 3)

Each cell is the output set for IF Range IS ... AND Pattern IS ... AND Header IS ... (defined as a
table in `FakeIpFIS.OUTCOME`). Because every combination has a rule, any input fires at least one rule.

| Range | Pattern | Header CONSISTENT | Header SUSPECT | Header FORGED |
|---|---|---|---|---|
| ROUTABLE | NATURAL | GENUINE | SUSPICIOUS | LIKELY_FAKE |
| ROUTABLE | PATTERNED | GENUINE | SUSPICIOUS | LIKELY_FAKE |
| ROUTABLE | ARTIFICIAL | QUESTIONABLE | SUSPICIOUS | LIKELY_FAKE |
| LIMITED | NATURAL | QUESTIONABLE | SUSPICIOUS | LIKELY_FAKE |
| LIMITED | PATTERNED | QUESTIONABLE | SUSPICIOUS | LIKELY_FAKE |
| LIMITED | ARTIFICIAL | SUSPICIOUS | LIKELY_FAKE | LIKELY_FAKE |
| RESERVED | NATURAL | SUSPICIOUS | LIKELY_FAKE | LIKELY_FAKE |
| RESERVED | PATTERNED | SUSPICIOUS | LIKELY_FAKE | LIKELY_FAKE |
| RESERVED | ARTIFICIAL | LIKELY_FAKE | LIKELY_FAKE | LIKELY_FAKE |

Design choices worth explaining in a viva:
- A **bad header** is the strongest single signal (forged headers are the textbook sign of spoofing).
- A **reserved range alone** is SUSPICIOUS (it can never be a normal public host) and becomes
  LIKELY_FAKE together with another red flag.
- A **tidy-looking pattern alone** never goes past QUESTIONABLE, because real addresses such as
  8.8.8.8 and 1.1.1.1 look typed too.

### 4. Inference engine

`is2/fuzzy/MamdaniEngine` is generic: antecedents are combined with fuzzy AND (min), rules that
conclude the same set are merged with max, the clipped output sets are aggregated, and a
200-point **centroid (center of gravity)** gives the crisp score. `FakeIpFIS` only defines the
variables and the rule table. The Detector prints every stage: fuzzification degrees, the rules
that fired with their strengths, and the centroid (an explainability trail).

### 5. Example inputs (Quick example menu)

| Example | Range | Pattern | Header | Score | Verdict |
|---|---|---|---|---|---|
| Normal public host + valid packet | 0 | 0 | 0 | 13 | GENUINE |
| Private address as an Internet source | 50 | 0 | 0 | 40 | QUESTIONABLE |
| Same private address on a LAN | 0 | 0 | 0 | 13 | GENUINE |
| Network address given to a host (192.168.1.64 /26, LAN) | 85 | 0 | 0 | 65 | SUSPICIOUS |
| Broadcast address given to a host (192.168.1.127 /26, LAN) | 85 | 0 | 0 | 65 | SUSPICIOUS |
| Hand-typed look (1.2.3.4) | 0 | 100 | 0 | 40 | QUESTIONABLE |
| Reserved Class E address (240.12.34.56) | 100 | 0 | 0 | 65 | SUSPICIOUS |
| Forged header (bad checksum, src = dst, TTL 0) | 0 | 0 | 100 | 89 | LIKELY FAKE |
| IPv6 documentation range | 85 | 50 | 0 | 65 | SUSPICIOUS |
| Made-up IPv6 (1234:5678:...) | 90 | 100 | 0 | 89 | LIKELY FAKE |
| Normal public IPv6 | 0 | 25 | 0 | 15 | GENUINE |

### 6. Limits (stated in the app too)

- This is an **offline heuristic** from the address block, its digit pattern and the optional
  packet bytes. It cannot prove spoofing and cannot tell whether an address is actually assigned
  or in use.
- Famous real addresses with tidy digits (8.8.8.8, 1.1.1.1) score QUESTIONABLE, not GENUINE: the
  detector cannot know they are real, which is exactly why Pattern alone is capped at QUESTIONABLE.
- Neighbouring addresses such as 192.168.1.1 and 192.168.1.12 are **not** treated as suspicious of
  each other: two devices on one subnet normally have close addresses.
- Centroid defuzzification is not strictly monotonic: raising one input can lower the score by up
  to about 2 points in a few places.

## History

SQLite table `tested_ips` (database version 3): address in canonical form, **prefix length and network**
(unique together, so the duplicate check is per subnet), protocol, timestamp, **score** and **verdict**.
Opening an older database keeps its rows (version 1 rows show as "not scored", rows from before
subnetting show no prefix and are matched and upgraded the next time that address is analysed).
Analysing an address already stored for the same subnet shows an "Already analysed" dialog with the
stored verdict and offers to re-analyse and update it. Long-press an entry to
remove it.

---

## Package map

```
com.example.packetviewer
├── MainActivity.java                 shared  (top tabs: CN | IS2)
├── adapters/ViewPagerAdapter.java    shared  (the two sections)
├── ui/SectionFragment.java           shared  (tabs + pager used by both sections)
│
├── cn/                               CN SECTION
│   ├── CnSectionFragment.java        (Viewer, Subnet, Transition)
│   ├── ViewerFragment.java
│   ├── SubnetFragment.java
│   ├── TransitionFragment.java
│   ├── models/IPv4HeaderModel.java, IPv6HeaderModel.java
│   └── utils/PacketParserUtils.java  hex parsing, bitwise header parsing, checksum
│            TransitionUtils.java     strict address parsing, IPv6 classification, header builders
│            SubnetCalculator.java    CIDR / split / VLSM (IPv4 + IPv6)
│   └── net/  Checksum, Packet, PacketBuilder, Nat64Prefix, Nat64Translator, Tunnels,
│             DualStack, Benchmark, PathModel, Scenario, TransitionDemo
│
└── is2/                              IS2 SECTION
    ├── Is2SectionFragment.java       (Detector, History)
    ├── DetectorFragment.java
    ├── DetectorExamples.java         one-tap demo inputs
    ├── HistoryFragment.java
    ├── database/IPDatabaseHelper.java, DbSchema.java
    ├── analysis/SubnetStep.java, RangeClassifier.java, PatternAnalyzer.java, HeaderForensics.java, FakeIpAnalyzer.java
    └── fuzzy/MamdaniEngine.java, FuzzyVariable.java, FuzzySet.java, FuzzyRule.java,
              MembershipFunction.java, TriangularMF.java, TrapezoidalMF.java,
              InferenceResult.java, FakeIpFIS.java
```

IS2 reuses a few CN classes: `SubnetCalculator` (step 0), `TransitionUtils` (strict address parsing, IPv6 classification and
the IPv4 header builder) and the One's Complement idea behind the header check.

Resources: `layout/` has `activity_main`, `fragment_section`, `fragment_viewer`,
`fragment_subnet`, `fragment_transition` (CN), `fragment_detector`, `fragment_history` (IS2), `view_ipv4_grid`,
`view_ipv6_grid`; `drawable/` the two grid-cell backgrounds; `values/` colours (including the four
verdict colours), strings and theme.

## Sample packet headers (valid, for the Detector's hex box and for testing)

**IPv4** (20-byte header, TCP, TTL 57; source 93.184.216.34, destination 8.8.4.4; checksum verified):
```
4500003C 1C464000 3906E38F 5DB8D822 08080404
```

**IPv6** (40-byte base header, TCP; source 2606:4700:4700::1111, destination 2a00:1450:4001:81b::200e):
```
60012345 00140640 26064700 47000000 00000000 00001111 2A001450 4001081B 00000000 0000200E
```

(The IPv4 sample used by earlier versions of this README had a wrong checksum, `B1E6` instead of
`9B22`, and would have been reported as altered.)

## Testing checklist

- [ ] Valid IPv4 / IPv6 entered in the Detector -> verdict, score bar and step-by-step trail shown, row stored.
- [ ] Invalid input (`999.999.1.1`, `1::2::3`) -> `setError()` shown, nothing stored.
- [ ] Each Quick example gives the verdict listed in the examples table.
- [ ] 192.168.1.50 with *Public Internet* -> QUESTIONABLE; with *Local network* -> GENUINE.
- [ ] Sample IPv4 header above with the matching IP -> Header 0; change the TTL byte `39` to `3A` -> Header 45 (checksum no longer verifies) and the verdict worsens.
- [ ] Hex shorter than a header, or an odd number of digits -> header check skipped, no crash.
- [ ] Re-entering a stored IP -> "Already analysed" dialog; Re-analyse updates the stored verdict, Cancel keeps it.
- [ ] 192.168.1.1 then 192.168.1.12 -> no similarity warning (neighbours are normal).
- [ ] Long-press a History entry -> "Remove stored IP?" dialog; Remove deletes only that row and updates the count; Cancel keeps it.
- [ ] Clear History -> table wiped, empty-state text shown.
- [ ] Upgrading an app that has version-1 history -> old rows kept, shown as "not scored".
- [ ] CN > Subnet: `192.168.1.77/26` -> network .64, broadcast .127, 62 hosts; `10.0.0.4/31` -> 2 usable; `10.1.2.3 255.0.255.0` -> "not contiguous" error; split `192.168.0.0/24` into /26 -> 4 subnets; VLSM `Sales 100 / Lab 50 / WAN 2` in `192.168.10.0/24` -> /25, /26, /31.
- [ ] IS2: `192.168.1.64` with prefix `26` (LAN) -> "NETWORK address" in STEP 0 and a worse verdict; the same address with `24` is a normal host. The same IP under two prefixes is stored as two entries; the same IP and prefix again -> "Already analysed".
- [ ] CN > Transition > NAT64 with the defaults -> every packet "checksums: all valid", the four refusal lines say dropped, a binding table appears. Use serverV4 `192.0.2.1` with the Well-Known Prefix -> the NOTE says it is refused; set prefix `2001:db8:64::` /96 -> it translates.
- [ ] Dual-stack with "IPv6 black-holed" ticked -> IPv4 wins at about 250 ms + the IPv4 RTT. Compare -> table of all five mechanisms; change link rate / loss / window and the limiter column changes.
- [ ] Running the same scenario twice gives slightly different "measured" ns figures (that is the benchmark working).
- [ ] Switching between CN and IS2 keeps what was typed.
