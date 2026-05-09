import {
    Callout,
    Card,
    CardBody,
    CardHeader,
    Divider,
    Grid,
    H1,
    H2,
    H3,
    Pill,
    Row,
    Stack,
    Stat,
    Table,
    Text,
    useHostTheme,
} from "cursor/canvas";

// =============================================================================
// ATSC 3.0 end-to-end gap analysis for atsc3_proto.
//
// Today the project owns one slice of the broadcast stack: the ALP / TLV-mux
// link layer plus a Seastar TCP gateway. This canvas inventories what would
// be needed on top (input API + content packaging + service signaling) and
// underneath (A/324 broadcast-gateway → exciter handoff) to drive an actual
// ATSC 3.0 RF transmitter end to end.
// =============================================================================

type Status = "done" | "in-flight" | "missing" | "external";

const STATUS_LABEL: Record<Status, string> = {
    done: "DONE",
    "in-flight": "PARTIAL",
    missing: "MISSING",
    external: "EXTERNAL",
};

const STATUS_PILL_TONE: Record<Status, "success" | "warning" | "deleted" | "info"> = {
    done: "success",
    "in-flight": "warning",
    missing: "deleted",
    external: "info",
};

const STATUS_ROW_TONE: Record<Status, "success" | "warning" | "danger" | "info"> = {
    done: "success",
    "in-flight": "warning",
    missing: "danger",
    external: "info",
};

// -----------------------------------------------------------------------------
// Stack overview — one row per logical layer of the broadcast pipeline.
// -----------------------------------------------------------------------------
const STACK: ReadonlyArray<{
    layer: string;
    blurb: string;
    status: Status;
}> = [
    {
        layer: "Operator UI / API",
        blurb: 'How a human or upstream system says "broadcast this"',
        status: "missing",
    },
    {
        layer: "Content packaging",
        blurb: "DASH segmenter, MMT packager, NRT file ingest, live RTMP/SRT/RTP",
        status: "missing",
    },
    {
        layer: "Service-layer signaling",
        blurb: "LLS (SLT, SystemTime, AEAT) + SLS (USBD, S-TSID, MPD, HELD)",
        status: "missing",
    },
    {
        layer: "Transport",
        blurb: "ROUTE/LCT for DASH, MMTP for MMT, Raptor10/RaptorQ FEC",
        status: "missing",
    },
    {
        layer: "Network (UDP/IP)",
        blurb: "Multicast IP packet building per service / signaling flow",
        status: "missing",
    },
    {
        layer: "Link layer (ALP + TLV-mux)",
        blurb: "ATSC A/330 — single packet_type, opaque payload, no segmentation",
        status: "in-flight",
    },
    {
        layer: "Gateway → Exciter (A/324)",
        blurb: "BBP framing, PLP scheduler, L1B/L1D, STLTP UDP, SFN time sync",
        status: "missing",
    },
    {
        layer: "Exciter / OFDM PHY (A/321 + A/322)",
        blurb: "Bootstrap, BCH+LDPC, bit interleaver, constellation, OFDM",
        status: "external",
    },
    {
        layer: "RF chain",
        blurb: "Power amp, mask filter, antenna",
        status: "external",
    },
];

// -----------------------------------------------------------------------------
// Detailed inventory — every concrete component, with spec citation + status.
// -----------------------------------------------------------------------------
type GapRow = {
    layer: string;
    spec: string;
    component: string;
    status: Status;
    notes: string;
};

const GAPS: ReadonlyArray<GapRow> = [
    // --- input / control plane ---
    {
        layer: "UI / API",
        spec: "—",
        component: "Web UI (operator dashboard)",
        status: "missing",
        notes: "Service list, PLP map, telemetry, push-to-broadcast",
    },
    {
        layer: "UI / API",
        spec: "—",
        component: "REST or gRPC control API",
        status: "missing",
        notes: "POST /services, /sources, /signaling/lls, GET /stats",
    },
    {
        layer: "UI / API",
        spec: "—",
        component: "Service config persistence",
        status: "missing",
        notes: "YAML or SQLite — survives restarts; schema-versioned",
    },
    // --- content sources ---
    {
        layer: "Content",
        spec: "ISO/IEC 23009-1",
        component: "MPEG-DASH segmenter",
        status: "missing",
        notes: "H.264 / HEVC + AAC / AC-4 → ISOBMFF segments + MPD",
    },
    {
        layer: "Content",
        spec: "A/331 §10",
        component: "MMT packager (MPU / MFU)",
        status: "missing",
        notes: "For MMT-delivered services (alternative to ROUTE/DASH)",
    },
    {
        layer: "Content",
        spec: "—",
        component: "NRT file ingest (drop folder)",
        status: "missing",
        notes: "Watch /in, schedule for ROUTE delivery",
    },
    {
        layer: "Content",
        spec: "—",
        component: "Live A/V ingest (RTMP / SRT / RTP)",
        status: "missing",
        notes: "From upstream encoders into the segmenter",
    },
    // --- service-layer signaling ---
    {
        layer: "Signaling",
        spec: "A/331 §6",
        component: "LLS framing + SLT",
        status: "missing",
        notes: "32-bit header + GZIPed XML on 224.0.23.60:4937",
    },
    {
        layer: "Signaling",
        spec: "A/331 §6.4",
        component: "LLS SystemTime",
        status: "missing",
        notes: "Wall-clock reference; one entry per LLS table set",
    },
    {
        layer: "Signaling",
        spec: "A/331 §6.5",
        component: "LLS AEAT (emergency alerts)",
        status: "missing",
        notes: "EAS / WEA-equivalent payload, optional but spec-required",
    },
    {
        layer: "Signaling",
        spec: "A/331 §6.6",
        component: "LLS RRT (region rating table)",
        status: "missing",
        notes: "Companion to EPG; rarely operationally critical",
    },
    {
        layer: "Signaling",
        spec: "A/331 §7",
        component: "SLS bundle (USBD / S-TSID / MPD / HELD)",
        status: "missing",
        notes: "Per-service signaling carried on its own ROUTE TSI",
    },
    // --- transport ---
    {
        layer: "Transport",
        spec: "A/331 §A.3",
        component: "ROUTE / LCT packetizer",
        status: "missing",
        notes: "RFC 5651 LCT + ALC sessions, source flow + repair flow",
    },
    {
        layer: "Transport",
        spec: "A/331 §10",
        component: "MMTP packetizer + signaling msgs",
        status: "missing",
        notes: "MMTP header, MFU mode, PA / MPI / MPT messages",
    },
    {
        layer: "Transport",
        spec: "RFC 5053 / 6330",
        component: "Raptor10 / RaptorQ FEC",
        status: "missing",
        notes: "Required for ROUTE robustness over a one-way link",
    },
    // --- network ---
    {
        layer: "Network",
        spec: "RFC 768 + RFC 791",
        component: "UDP / IPv4 builder + checksums",
        status: "missing",
        notes: "Trivial codegen target; multicast addr per service",
    },
    // --- link (this is us) ---
    {
        layer: "Link",
        spec: "A/330 §5.2",
        component: "ALP base header (16-bit)",
        status: "done",
        notes: "Single packet_type, opaque payload, ≤ 2047 B (M3)",
    },
    {
        layer: "Link",
        spec: "A/330 §5.2.4",
        component: "ALP segmentation + concatenation",
        status: "missing",
        notes: "For IP packets > MTU and small-packet aggregation",
    },
    {
        layer: "Link",
        spec: "A/330 §5.2.6",
        component: "ALP additional headers",
        status: "missing",
        notes: "Sub-stream ID, sequence number, header compression context",
    },
    {
        layer: "Link",
        spec: "A/330 Annex A",
        component: "TLV multiplex (single packet)",
        status: "done",
        notes: "Single packet, 16-bit length, opaque payload (M3)",
    },
    {
        layer: "Link",
        spec: "A/330 Annex A",
        component: "TLV-mux frame composition (N packets)",
        status: "done",
        notes: "M6 nested-protocol via repeated:; tlv_mux_frame.yaml",
    },
    // --- broadcast gateway → exciter ---
    {
        layer: "Gateway↔Exc",
        spec: "A/322 §5.1",
        component: "Baseband packet (BBP) framing",
        status: "missing",
        notes: "BBP type + length + ALP payload + padding to PLP cell",
    },
    {
        layer: "Gateway↔Exc",
        spec: "A/324",
        component: "PLP scheduler",
        status: "missing",
        notes: "Map IP / ALP packets → PLPs by service / QoS / FEC class",
    },
    {
        layer: "Gateway↔Exc",
        spec: "A/322 §5.6",
        component: "L1 signaling (L1B 200b + L1D var)",
        status: "missing",
        notes: "FFT, GI, pilot pattern, MOD/COD, subframe layout per PLP",
    },
    {
        layer: "Gateway↔Exc",
        spec: "A/324",
        component: "STLTP packetizer (UDP wire)",
        status: "missing",
        notes: "{BBP-per-PLP, L1B, L1D, Time, Preamble}",
    },
    {
        layer: "Gateway↔Exc",
        spec: "A/324 §6",
        component: "Time / SFN sync (PTPv2)",
        status: "missing",
        notes: "GPS-disciplined source; coherent emission across TXs",
    },
    {
        layer: "Gateway↔Exc",
        spec: "A/324",
        component: "Preamble Data Pipe (PDP)",
        status: "missing",
        notes: "Low-bitrate sideband for L1 changes between frames",
    },
    // --- exciter / RF (out of scope for atsc3_proto) ---
    {
        layer: "Exciter",
        spec: "A/321",
        component: "Bootstrap signal generator",
        status: "external",
        notes: "OOK preamble; allows cold tuners to discover frames",
    },
    {
        layer: "Exciter",
        spec: "A/322 §6.5",
        component: "BCH (outer) + LDPC (inner) FEC",
        status: "external",
        notes: "Per-PLP block coding driven by L1D modcod settings",
    },
    {
        layer: "Exciter",
        spec: "A/322",
        component: "Bit interleave + constellation map",
        status: "external",
        notes: "QPSK / 16 / 64 / 256 / 1024 / 4096-QAM (NUC)",
    },
    {
        layer: "Exciter",
        spec: "A/322",
        component: "Time interleaver per PLP",
        status: "external",
        notes: "Convolutional or hybrid; depth from L1D",
    },
    {
        layer: "Exciter",
        spec: "A/322",
        component: "OFDM modulator (8K / 16K / 32K FFT)",
        status: "external",
        notes: "Pilots, GI, frame structure → IFFT → I/Q baseband",
    },
    {
        layer: "RF",
        spec: "—",
        component: "Up-converter, PA, mask filter, antenna",
        status: "external",
        notes: "Broadcaster's transmitter plant",
    },
    // --- ops / cross-cutting ---
    {
        layer: "Ops",
        spec: "—",
        component: "Prometheus / OpenTelemetry metrics",
        status: "missing",
        notes: "bytes_in, payloads, encode_errors per shard / PLP / service",
    },
    {
        layer: "Ops",
        spec: "—",
        component: "Auth + TLS on the control API",
        status: "missing",
        notes: "mTLS or token; required before any production exposure",
    },
    {
        layer: "Ops",
        spec: "—",
        component: "Health + readiness probes",
        status: "missing",
        notes: "/healthz, /readyz for orchestrators",
    },
];

// -----------------------------------------------------------------------------
// Roadmap — pragmatic order to close the gaps. Each milestone unlocks a
// concrete capability you can demo end-to-end with real hardware.
// -----------------------------------------------------------------------------
const ROADMAP: ReadonlyArray<{
    id: string;
    title: string;
    blurb: string;
    unlocks: string;
    closes: string[];
}> = [
    {
        id: "M7",
        title: "Control plane",
        blurb:
            "REST or gRPC API + a service-config YAML schema persisted under /var/lib/atsc3_proto. " +
            "Replaces the current TCP-only ingress with a first-class operator surface: declare a " +
            "service, attach a content source, push it. Includes a CLI (atsc3ctl) and a thin web UI " +
            "as the smallest deliverable that an operator can actually use.",
        unlocks: 'A human (or upstream system) can say "broadcast this"',
        closes: ["Web UI", "REST/gRPC API", "Service config persistence"],
    },
    {
        id: "M8",
        title: "Network + transport (UDP/IP, ROUTE/LCT, MMTP)",
        blurb:
            "Move from opaque length-framed payloads to real broadcast-shaped traffic. UDP/IPv4 builder " +
            "(another codegen YAML), then ROUTE/LCT for DASH delivery and MMTP for MMT delivery. " +
            "ALP encapsulation already in place picks up real IP packets instead of opaque blobs. " +
            "Adds Raptor10/RaptorQ FEC for the one-way path.",
        unlocks: "Real IP multicast packets ride through ALP+TLV-mux",
        closes: [
            "UDP/IPv4 builder",
            "ROUTE/LCT packetizer",
            "MMTP packetizer",
            "Raptor10/RaptorQ FEC",
        ],
    },
    {
        id: "M9",
        title: "Service-layer signaling",
        blurb:
            "Generate the SLT/SystemTime/AEAT LLS table set and the per-service SLS bundle " +
            "(USBD, S-TSID, MPD, HELD). Without this no ATSC 3.0 receiver can discover the broadcast " +
            "or know how to decode it. Naturally splits into three sub-tasks: an XML emitter (use " +
            "TinyXML2 or hand-rolled), the LLS framer (32-bit header + GZIP), and the per-service " +
            "scheduler that puts SLS on its own TSI.",
        unlocks: "Off-the-shelf ATSC 3.0 receivers can tune your broadcast",
        closes: [
            "LLS framing + SLT",
            "LLS SystemTime",
            "LLS AEAT",
            "LLS RRT",
            "SLS bundle",
        ],
    },
    {
        id: "M10",
        title: "A/324 STLTP (broadcast gateway → exciter)",
        blurb:
            "The biggest payoff. Implement the A/324 Studio-Transmitter Link Tunneling Protocol: " +
            "BBP framing, PLP scheduler, L1B + L1D signaling, STLTP UDP wire format, and PTPv2-based " +
            "time alignment for SFN. After this lands, atsc3_proto plugs into any commercial exciter " +
            "(GatesAir Maxiva XTE, Sinclair RoVer, Enensys MUX-3000) over plain Ethernet and the " +
            "exciter happily emits OFDM on RF. This is the canonical broadcast-gateway surface.",
        unlocks: "Real RF transmission via off-the-shelf exciters",
        closes: [
            "Baseband packet framing",
            "PLP scheduler",
            "L1B / L1D",
            "STLTP packetizer",
            "Time / SFN sync",
            "Preamble Data Pipe",
        ],
    },
    {
        id: "M11",
        title: "Content packaging (DASH + MMT)",
        blurb:
            "The last piece for a true end-to-end demo without an external encoder/packager: an " +
            "embedded MPEG-DASH segmenter (wrap libavformat / GPAC) plus an MMT packager. Live A/V " +
            "ingest via SRT/RTMP/RTP feeds the segmenter, segments stream into the M8 ROUTE/MMTP " +
            "transport. Heaviest milestone in lines of code; defer until the whole pipe is otherwise " +
            "exercised.",
        unlocks: "Self-contained broadcast: live encoder → atsc3_proto → exciter",
        closes: [
            "MPEG-DASH segmenter",
            "MMT packager (MPU/MFU)",
            "NRT file ingest",
            "Live A/V ingest (RTMP/SRT/RTP)",
        ],
    },
    {
        id: "M12",
        title: "ALP enrichment + Ops",
        blurb:
            "Round out the link layer with ALP segmentation + concatenation (so jumbo IP packets and " +
            "small signaling bursts behave correctly under MTU pressure) and the additional-headers " +
            "stream. In parallel, ship Prometheus metrics, /healthz, /readyz, mTLS on the control API, " +
            "and structured JSON logs.",
        unlocks: "Production-readable telemetry + clean MTU semantics",
        closes: [
            "ALP segmentation/concatenation",
            "ALP additional headers",
            "Prometheus metrics",
            "Auth + TLS",
            "Health + readiness probes",
        ],
    },
];

// -----------------------------------------------------------------------------
// Main canvas component.
// -----------------------------------------------------------------------------
export default function Atsc3EndToEndGaps() {
    const theme = useHostTheme();

    const totalGaps = GAPS.length;
    const doneGaps = GAPS.filter((g) => g.status === "done").length;
    const partialGaps = GAPS.filter((g) => g.status === "in-flight").length;
    const missingGaps = GAPS.filter((g) => g.status === "missing").length;
    const externalGaps = GAPS.filter((g) => g.status === "external").length;
    const inScopeMissing = missingGaps + partialGaps;
    const inScopeTotal = doneGaps + missingGaps + partialGaps;
    const pctDone = Math.round((doneGaps / inScopeTotal) * 100);

    return (
        <Stack gap={28}>
            {/* ============================================================ */}
            {/* HERO                                                           */}
            {/* ============================================================ */}
            <Stack gap={12}>
                <H1>ATSC 3.0 end-to-end: from atsc3_proto to RF</H1>
                <Text tone="secondary">
                    Today the project owns one slice of the broadcast stack — the ALP +
                    TLV-mux link layer plus a Seastar TCP gateway. To answer
                    {' "'}<Text as="span" weight="semibold">put this content into ATSC 3.0 and pass it to the exciter</Text>{'" '}
                    you need a layer above (input API + content packaging + service
                    signaling) and a layer below (the A/324 broadcast-gateway → exciter
                    handoff). Below is the inventory of every protocol-level component,
                    grouped by layer, with the recommended build order at the bottom.
                </Text>
            </Stack>

            <Grid columns={4} gap={16}>
                <Stat value={doneGaps} label="Done in atsc3_proto" tone="success" />
                <Stat value={inScopeMissing} label="Missing (in scope)" tone="warning" />
                <Stat value={externalGaps} label="Out of scope (exciter / RF)" tone="info" />
                <Stat value={`${pctDone}%`} label="In-scope coverage" />
            </Grid>

            <Divider />

            {/* ============================================================ */}
            {/* WHAT SHIPS TODAY                                               */}
            {/* ============================================================ */}
            <Stack gap={12}>
                <H2>What atsc3_proto ships today</H2>
                <Grid columns={2} gap={12}>
                    <BulletGroup
                        title="Inputs the gateway accepts"
                        items={[
                            "TCP length-prefix ingress: [u32 BE length] [payload]",
                            "Per-shard SO_REUSEPORT load balancing on the listen socket",
                            "RTCM v3 frames as a special-case payload via mmt_probe --rtcm-file",
                        ]}
                    />
                    <BulletGroup
                        title="What it produces on the wire"
                        items={[
                            "ALP packet: 16-bit base header + opaque payload (≤ 2047 B)",
                            "TLV-mux packet: 24-bit header + ALP payload (≤ 65 535 B)",
                            "Sinks: stdout://, file:///path, null:// (throughput soak)",
                        ]}
                    />
                    <BulletGroup
                        title="Codec generator"
                        items={[
                            "tools/codegen.py reads protocol/*.yaml → C++ types/decoder/encoder/JSON",
                            "Recursive nested support via repeated: (M6) — see tlv_mux_frame.yaml",
                            "MSB-first bit reader/writer in lib/runtime/",
                        ]}
                    />
                    <BulletGroup
                        title="Test harness"
                        items={[
                            "Per-protocol fixture round-trip tests (auto-generated)",
                            "tools/smoke/codec_smoke.py — pure-Python golden checks (25 cases)",
                            "scripts/integration_test.sh — gw + mmt_probe loopback in 1 process",
                        ]}
                    />
                </Grid>
            </Stack>

            <Divider />

            {/* ============================================================ */}
            {/* PROTOCOL STACK DIAGRAM                                         */}
            {/* ============================================================ */}
            <Stack gap={12}>
                <H2>Protocol stack — where each gap lives</H2>
                <Text tone="secondary" size="small">
                    Top is closest to the operator; bottom is closest to RF. Layers
                    flagged EXTERNAL belong to the exciter or transmitter plant and
                    are intentionally out of scope for atsc3_proto.
                </Text>
                <Stack gap={6}>
                    {STACK.map((row, idx) => (
                        <Row
                            key={row.layer}
                            gap={16}
                            align="center"
                            style={{
                                paddingTop: 10,
                                paddingBottom: 10,
                                borderTop:
                                    idx === 0
                                        ? `1px solid ${theme.stroke.tertiary}`
                                        : "none",
                                borderBottom: `1px solid ${theme.stroke.tertiary}`,
                            }}
                        >
                            <div style={{ width: 24 }}>
                                <Text tone="tertiary" size="small">
                                    {String(idx + 1).padStart(2, "0")}
                                </Text>
                            </div>
                            <div style={{ width: 240, flexShrink: 0 }}>
                                <Text weight="semibold">{row.layer}</Text>
                            </div>
                            <div style={{ flex: 1, minWidth: 0 }}>
                                <Text tone="secondary">{row.blurb}</Text>
                            </div>
                            <div style={{ width: 110, flexShrink: 0, textAlign: "right" }}>
                                <Pill size="sm" tone={STATUS_PILL_TONE[row.status]}>
                                    {STATUS_LABEL[row.status]}
                                </Pill>
                            </div>
                        </Row>
                    ))}
                </Stack>
            </Stack>

            <Divider />

            {/* ============================================================ */}
            {/* DETAILED GAP TABLE                                             */}
            {/* ============================================================ */}
            <Stack gap={12}>
                <H2>Detailed gap inventory</H2>
                <Text tone="secondary" size="small">
                    Every concrete component with its ATSC / IETF spec citation and
                    current status. Row color matches the status pill.
                </Text>
                <Table
                    headers={["Layer", "Spec", "Component", "Status", "Notes"]}
                    columnAlign={["left", "left", "left", "left", "left"]}
                    rows={GAPS.map((g) => [
                        g.layer,
                        g.spec,
                        g.component,
                        STATUS_LABEL[g.status],
                        g.notes,
                    ])}
                    rowTone={GAPS.map((g) => STATUS_ROW_TONE[g.status])}
                    striped
                    stickyHeader
                />
                <Row gap={16} wrap>
                    <LegendChip label="DONE" tone="success">
                        Implemented in atsc3_proto today
                    </LegendChip>
                    <LegendChip label="PARTIAL" tone="warning">
                        Codec is in but the layer is not feature-complete
                    </LegendChip>
                    <LegendChip label="MISSING" tone="deleted">
                        In scope, not yet implemented
                    </LegendChip>
                    <LegendChip label="EXTERNAL" tone="info">
                        Belongs to the exciter / RF chain
                    </LegendChip>
                </Row>
            </Stack>

            <Divider />

            {/* ============================================================ */}
            {/* ROADMAP                                                        */}
            {/* ============================================================ */}
            <Stack gap={12}>
                <H2>Recommended build order</H2>
                <Text tone="secondary" size="small">
                    Each milestone is small enough to land in 1–3 weeks of focused
                    work and unlocks a concrete capability you can demo end-to-end.
                </Text>
                <Stack gap={12}>
                    {ROADMAP.map((m) => (
                        <Card key={m.id}>
                            <CardHeader
                                trailing={
                                    <Pill size="sm" tone="info">
                                        {m.closes.length} gaps
                                    </Pill>
                                }
                            >
                                {m.id} — {m.title}
                            </CardHeader>
                            <CardBody>
                                <Stack gap={10}>
                                    <Text>{m.blurb}</Text>
                                    <Row gap={6} wrap align="center">
                                        <Text tone="tertiary" size="small">
                                            Unlocks:
                                        </Text>
                                        <Text size="small" weight="semibold">
                                            {m.unlocks}
                                        </Text>
                                    </Row>
                                    <Row gap={6} wrap>
                                        {m.closes.map((c) => (
                                            <Pill key={c} size="sm">
                                                {c}
                                            </Pill>
                                        ))}
                                    </Row>
                                </Stack>
                            </CardBody>
                        </Card>
                    ))}
                </Stack>
            </Stack>

            <Divider />

            {/* ============================================================ */}
            {/* OUT OF SCOPE                                                   */}
            {/* ============================================================ */}
            <Stack gap={12}>
                <H2>Beyond the gateway (intentionally external)</H2>
                <Callout tone="info" title="Where atsc3_proto stops">
                    <Stack gap={6}>
                        <Text>
                            atsc3_proto's job ends at the A/324 STLTP wire (M10). The
                            exciter consumes those packets and is responsible for
                            generating the bootstrap (A/321), the inner BCH+LDPC FEC,
                            the bit interleaver, the constellation mapper (QPSK through
                            4096-QAM NUC), the time interleaver, and the OFDM modulator
                            itself (A/322). The transmitter plant then handles
                            up-conversion, the power amplifier, the mask filter, and
                            the antenna.
                        </Text>
                        <Text>
                            Reference exciters that consume A/324 STLTP today: GatesAir
                            Maxiva XTE, Sinclair RoVer, Enensys MUX-3000, Harmonic
                            Electra X3. Any of them can act as the downstream peer
                            once M10 lands.
                        </Text>
                    </Stack>
                </Callout>
            </Stack>

            <Divider />

            {/* ============================================================ */}
            {/* SHORT-TERM PRACTICAL ANSWER                                    */}
            {/* ============================================================ */}
            <Stack gap={12}>
                <H2>If you want a usable demo this week</H2>
                <Grid columns={2} gap={12}>
                    <Card>
                        <CardHeader>Smallest input surface</CardHeader>
                        <CardBody>
                            <Stack gap={8}>
                                <Text>
                                    Skip the full REST API. Add a single
                                    {' '}<Text as="span" weight="semibold">
                                        POST /ingest
                                    </Text>{' '}
                                    HTTP endpoint inside the existing Seastar gateway
                                    (use seastar/http) that accepts a JSON envelope:
                                </Text>
                                <Text size="small">
                                    {`{ "service_id": 1, "type": "rtcm" | "raw" | "lls", "payload_b64": "..." }`}
                                </Text>
                                <Text>
                                    The gateway routes by `type` into the existing
                                    encoder pipeline, plus a new
                                    {' '}<Text as="span" weight="semibold">lls://</Text>{' '}
                                    sink that emits LLS-framed XML on a configurable
                                    multicast IP. Two days of work.
                                </Text>
                            </Stack>
                        </CardBody>
                    </Card>
                    <Card>
                        <CardHeader>Smallest output surface</CardHeader>
                        <CardBody>
                            <Stack gap={8}>
                                <Text>
                                    Add a third sink:
                                    {' '}<Text as="span" weight="semibold">
                                        stltp://exciter:30000
                                    </Text>{' '}
                                    that wraps each TLV-mux frame in a minimal A/324
                                    STLTP packet (BBP for one PLP, hard-coded L1B/L1D,
                                    monotonic-counter timestamps, no PTP).
                                </Text>
                                <Text>
                                    Doesn't pass conformance, but a real exciter on the
                                    bench will accept it and emit OFDM. Lets you exercise
                                    the whole chain on a single PLP, single MODCOD before
                                    investing in the full M10 surface.
                                </Text>
                            </Stack>
                        </CardBody>
                    </Card>
                </Grid>
            </Stack>

            <Spacer8 />
        </Stack>
    );
}

// -----------------------------------------------------------------------------
// Local helpers (single-file rule — no external modules).
// -----------------------------------------------------------------------------

function BulletGroup({ title, items }: { title: string; items: string[] }) {
    const theme = useHostTheme();
    return (
        <Stack gap={8}>
            <H3>{title}</H3>
            <Stack gap={4}>
                {items.map((item) => (
                    <Row key={item} gap={8} align="start">
                        <div
                            style={{
                                width: 4,
                                height: 4,
                                borderRadius: 2,
                                marginTop: 9,
                                background: theme.fill.tertiary,
                                flexShrink: 0,
                            }}
                        />
                        <Text>{item}</Text>
                    </Row>
                ))}
            </Stack>
        </Stack>
    );
}

function LegendChip({
    label,
    tone,
    children,
}: {
    label: string;
    tone: "success" | "warning" | "deleted" | "info";
    children: React.ReactNode;
}) {
    return (
        <Row gap={8} align="center">
            <Pill size="sm" tone={tone}>
                {label}
            </Pill>
            <Text tone="secondary" size="small">
                {children}
            </Text>
        </Row>
    );
}

function Spacer8() {
    return <div style={{ height: 8 }} />;
}
