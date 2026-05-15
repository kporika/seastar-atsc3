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
// Generic intro to ATSC 3.0 ("NextGen TV") and the suite of ATSC standards
// (A/321/A/322 PHY, A/324 STLTP, A/330 ALP + TLV multiplex, A/331 signaling
// + content delivery), with this project's reference scope (A/330) called
// out. The body of the canvas inventories every protocol-level component
// between an operator's "broadcast this" and the RF exciter, grouped by
// layer, and recommends a build order.
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
        blurb: 'How a human or upstream system says "broadcast this" — HTTP admin, tools/atsc3ctl.py, webapp Operator tab (dev proxy to admin)',
        status: "in-flight",
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
        blurb: "ROUTE/LCT for DASH, MMTP for MMT, Raptor10/RaptorQ FEC — LCT header word-0 YAML landed",
        status: "in-flight",
    },
    {
        layer: "Network (UDP/IP)",
        blurb: "Multicast IP packet building per service / signaling flow — IPv4+UDP builder in lib/runtime",
        status: "in-flight",
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
    /** When true, row is included in the "Declared repo roadmap (A/330 lab link layer)" stats below. */
    roadmap?: boolean;
};

const GAPS: ReadonlyArray<GapRow> = [
    // --- input / control plane ---
    {
        layer: "UI / API",
        spec: "—",
        component: "Web UI (operator dashboard)",
        status: "in-flight",
        notes:
            "Thin Operator tab in webapp (dev: Vite proxy /__atsc3_admin → ATSC3_ADMIN_URL); config/services/metrics/sink; full dashboard (PLP map, telemetry, push-to-broadcast) still missing; static GitHub Pages build has no admin backend",
    },
    {
        layer: "UI / API",
        spec: "—",
        component: "REST or gRPC control API",
        status: "in-flight",
        notes:
            "--admin-http: POST /ingest, GET /metrics, GET /config, POST /config/sink + PATCH/PUT /config (mutators {\"sink_uri\"} only → global sink swap); GET /services, POST, PATCH (?id), DELETE (?id); optional Bearer (--admin-bearer-token) on mutators + POST /ingest; optional PEM HTTPS (--admin-tls-cert + --admin-tls-key); optional service_id on ingest → HTTP routes via row sink_uri (TCP ingress --sink only); --services-state-file schema_version 2 (reactor file I/O); tools/atsc3ctl.py mirrors; missing: gRPC, operator YAML/SQLite bootstrap, client mTLS, richer schema",
    },
    {
        layer: "UI / API",
        spec: "—",
        component: "Service config persistence",
        status: "in-flight",
        notes:
            "Optional --services-state-file JSON for /services (shard 0; load/persist via reactor file + dma_read / output_stream + rename — no fstream in seastar::async); examples/gw.operator.example.json; full operator YAML/SQLite + schema versioning still missing",
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
        status: "in-flight",
        notes:
            "Table 6.1 + gzip via lls:// sink; lls_table6_1.hh; tools/m9_lls_pack.py + fixtures/lls/minimal_slt.xml; SLT scheduler / full A/331 not built",
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
        status: "in-flight",
        notes:
            "protocol/lct_rfc5651_word0.yaml — RFC 5651 first 32-bit LCT header word (codegen + fixtures); gw --prepend-lct-word0 adds word-0 (optional --lct-include-tsi / --lct-include-toi, or both: TSI+TOI ⇒ header_length_words=3; CCI omitted lab) inside ALP ahead of payloads; full ALC/ROUTE sessions + source/repair still missing",
    },
    {
        layer: "Transport",
        spec: "A/331 §10",
        component: "MMTP packetizer + signaling msgs",
        status: "in-flight",
        notes:
            "mmtp_desc + mmtp_desc_loop = Annex A.5 TLVs; mmtp_header_word0 + ts_psn + counter32 + extension (ISO/IEC 23008-1; one extension TLV per YAML); isobmff_prefix + du_length16 (A=1) + du_header timed/non-timed (FT=2); gfd_header (type 0x01); gw --prepend-mmtp-word0 (word-0 before optional LCT); MFU/PA/MPI/MPT payload modes + signalling payload header (0x02) + gw ts_psn/extension stitch + multi-ext assembly still missing",
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
        status: "in-flight",
        notes:
            "lib/runtime/ipv4_udp.{hh,cc} encapsulate_ipv4_udp + checksums; protocol/lct_rfc5651_word0.yaml (LCT first word) + gw --prepend-lct-word0 lab prefix (optional BE32 TSI / TOI(O=1), or both RFC order) inside ALP; gw --prepend-mmtp-word0 before optional LCT; full ROUTE/ALC/MMTP wire not in gw yet",
    },
    // --- link (this is us) ---
    {
        layer: "Link",
        spec: "A/330 §5.2",
        component: "ALP base header (16-bit)",
        status: "done",
        roadmap: true,
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
        roadmap: true,
        notes: "Single packet, 16-bit length, opaque payload (M3)",
    },
    {
        layer: "Link",
        spec: "A/330 Annex A",
        component: "TLV-mux frame composition (N packets)",
        status: "done",
        roadmap: true,
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
        status: "in-flight",
        notes:
            "M10 wire format still missing; stltp://host:port lab wrap of TLV-mux in gw/sink.cc",
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
        status: "in-flight",
        notes:
            "GET /metrics text exposition when --admin-http is set (aggregate counters); OTEL + PLP/service labels missing",
    },
    {
        layer: "Ops",
        spec: "—",
        component: "Auth + TLS on the control API",
        status: "in-flight",
        notes:
            "Bearer token (--admin-bearer-token) on mutators + POST /ingest; HTTPS admin with PEM cert/key; client mTLS / OIDC / audit trail still missing for production",
    },
    {
        layer: "Ops",
        spec: "—",
        component: "Health + readiness probes",
        status: "in-flight",
        notes: "GET /healthz and GET /readyz on the --admin-http bind address",
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
            "service, attach a content source, push it. Minimal M7 surface shipped: stdlib CLI (atsc3ctl), " +
            "thin Operator web tab (dev), JSON example for compose, PATCH /services?id= per-row sink_uri, " +
            "optional Bearer + HTTPS listener, POST /ingest service_id routing (HTTP only), --services-state-file. " +
            "Full YAML/SQLite schema, gRPC, and client mTLS remain future work.",
        unlocks:
            "A human (or upstream system) can drive admin HTTP from browser (dev), webapp Operator tab, or tools/atsc3ctl.py; optional service JSON via --services-state-file; global sink hot-swap; per-service HTTP ingest sink selection",
        closes: [
            "Web UI (partial: Operator tab + dev proxy; full dashboard still open)",
            "REST (partial: admin-http + atsc3ctl + PATCH /services + bearer + HTTPS; gRPC + client mTLS + YAML/SQLite still open)",
            "Service config persistence (partial: --services-state-file + example JSON)",
        ],
    },
    {
        id: "M8",
        title: "Network + transport (UDP/IP, ROUTE/LCT, MMTP)",
        blurb:
            "Move from opaque length-framed payloads to real broadcast-shaped traffic. " +
            "UDP/IPv4 is already in C++ (lib/runtime/ipv4_udp + udp:// / ipv4udp-file:// sinks). " +
            "protocol/lct_rfc5651_word0.yaml anchors RFC 5651 first header word; atsc3_gw --prepend-lct-word0 prefixes inside ALP; optional BE32 --lct-include-tsi (--lct-tsi) / --lct-include-toi (--lct-toi); both ⇒ TSI then TOI (hdr_len_words=3, max user 2035 vs 2039 word-0-only + one field vs 2043 word-0-only). --prepend-mmtp-word0 adds MMTP packet header word-0 before optional LCT. " +
            "Full ROUTE/LCT sessions, MMTP payload modes, and Raptor10/RaptorQ FEC remain. " +
            "ALP encapsulation already accepts opaque payloads. Next: MMTP signalling payload header YAML (type 0x02); optional gw ts_psn + mmt_probe strip/verify parity.",
        unlocks: "Real IP multicast packets ride through ALP+TLV-mux",
        closes: [
            "UDP/IPv4 builder (partial: C++ + sinks)",
            "ROUTE/LCT packetizer (partial: word-0 YAML + gw prepend + optional TSI/TOI bytes)",
            "MMTP packetizer (partial: mmtp_header_* + mmtp_desc + gw --prepend-mmtp-word0)",
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
            "stream. Ops baseline is already on --admin-http (text /metrics, /healthz, /readyz, optional " +
            "Bearer + PEM HTTPS); M12 finishes production hardening: OTEL + PLP/service labels, client mTLS, " +
            "OIDC/audit trails, structured JSON logs, deeper readiness as needed.",
        unlocks: "Production-readable telemetry + clean MTU semantics",
        closes: [
            "ALP segmentation/concatenation",
            "ALP additional headers",
            "Prometheus / OpenTelemetry metrics",
            "Auth + TLS (client mTLS, OIDC, audits)",
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

    const roadmapRows = GAPS.filter((g) => g.roadmap === true);
    const roadmapDone = roadmapRows.filter((g) => g.status === "done").length;
    const roadmapOpen = roadmapRows.filter(
        (g) => g.status === "missing" || g.status === "in-flight"
    ).length;
    const roadmapTotal = roadmapRows.length;
    const pctRoadmap =
        roadmapTotal > 0 ? Math.round((roadmapDone / roadmapTotal) * 100) : 0;

    return (
        <Stack gap={28}>
            {/* ============================================================ */}
            {/* HERO                                                           */}
            {/* ============================================================ */}
            <Stack gap={12}>
                <H1>ATSC 3.0 end-to-end: from atsc3_proto to RF</H1>
                <Text tone="secondary">
                    ATSC 3.0 ("NextGen TV") is the IP-native next-generation digital
                    terrestrial broadcast standard from the Advanced Television Systems
                    Committee, replacing the MPEG-TS pipeline of ATSC 1.0. The stack is
                    split across half a dozen specs: an OFDM/LDPC physical layer
                    (A/321 bootstrap + A/322 PHY), a studio-to-transmitter scheduler and
                    tunnel (A/324 STLTP), a link layer that carries IP packets over the
                    air (<Text as="span" weight="semibold">A/330 — ALP + TLV multiplex</Text>),
                    and service signaling plus content delivery
                    (A/331 LLS/SLS, ROUTE/DASH, MMTP). This project takes{' '}
                    <Text as="span" weight="semibold">A/330 as its reference scope</Text>{' '}
                    and implements it as a YAML-driven C++ codec generator plus a Seastar
                    gateway. Below is the full inventory of every protocol-level component
                    between an operator's "broadcast this" and the RF exciter, grouped by
                    layer, with the recommended build order at the bottom.
                </Text>
                <Text tone="secondary" size="small">
                    Closing every row is multi-year work (milestones M7–M12): packaging,
                    signaling, transport, production A/324 STLTP, etc. The table tracks status
                    incrementally as the repo grows—expect small deltas per change, not a
                    single leap to RF.
                </Text>
                <Text tone="secondary" size="small">
                    Driving every inventory row to DONE would mean implementing the entire
                    NextGen TV chain (and the exciter PHY) in one codebase; that is not the
                    goal of atsc3_proto. EXTERNAL rows stay with the transmitter vendor; many
                    MISSING rows are industry-sized programs. Use M7–M12 as the staged roadmap
                    for what may land here.
                </Text>
            </Stack>

            <Grid columns={4} gap={16}>
                <Stat value={doneGaps} label="Gap rows DONE" tone="success" />
                <Stat value={inScopeMissing} label="PARTIAL + MISSING (in scope)" tone="warning" />
                <Stat value={externalGaps} label="Out of scope (exciter / RF)" tone="info" />
                <Stat value={`${pctDone}%`} label="DONE ÷ in-scope rows" tone="info" />
            </Grid>

            <Stack gap={8}>
                <Text weight="semibold" size="small">
                    Declared in-repo roadmap (A/330 lab link layer only)
                </Text>
                <Text tone="secondary" size="small">
                    Rows with <Text as="span" weight="semibold">roadmap: true</Text> in the table
                    source are the subset this repository explicitly tracks for “all link-layer
                    lab gaps closed”; they are independent of the full operator→RF inventory above.
                </Text>
            </Stack>
            <Grid columns={4} gap={16}>
                <Stat value={roadmapTotal} label="Roadmap rows" tone="info" />
                <Stat value={roadmapDone} label="Roadmap DONE" tone="success" />
                <Stat value={roadmapOpen} label="Roadmap open" tone={roadmapOpen === 0 ? "success" : "warning"} />
                <Stat value={`${pctRoadmap}%`} label="DONE ÷ roadmap rows" tone="success" />
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
                            "Optional HTTP admin (--admin-http): POST /ingest, GET /config, POST /config/sink + PATCH/PUT /config (mutators {\"sink_uri\"} only), GET/POST/PATCH/DELETE /services, optional --prepend-lct-word0 (--lct-codepoint; optional --lct-include-tsi --lct-tsi and/or --lct-include-toi --lct-toi), optional --prepend-mmtp-word0 (--mmtp-payload-type, --mmtp-packet-id), optional --services-state-file, GET /healthz, /readyz, /metrics; optional --admin-bearer-token + PEM TLS (--admin-tls-cert/--admin-tls-key); Operator tab via Vite /__atsc3_admin → ATSC3_ADMIN_URL; tools/atsc3ctl.py",
                        ]}
                    />
                    <BulletGroup
                        title="What it produces on the wire"
                        items={[
                            "ALP packet: 16-bit base header + opaque payload (≤ 2047 B)",
                            "TLV-mux packet: 24-bit header + ALP payload (≤ 65 535 B)",
                            "Sinks: stdout://, file:///path, null://, udp://host:port (TLV-mux/UDP), ipv4udp-file://…?src=&dst=&… (M8 wire append), stltp://host:port (lab STLTP/UDP), lls://[host:port][?table=&group=&gcm1=] (A/331 LLS + gzip; default 224.0.23.60:4937)",
                        ]}
                    />
                    <BulletGroup
                        title="Codec generator"
                        items={[
                            "tools/codegen.py reads protocol/*.yaml → C++ types/decoder/encoder/JSON",
                            "Recursive nested support via repeated: (M6) — see tlv_mux_frame.yaml",
                            "MSB-first bit reader/writer in lib/runtime/",
                            "lib/runtime/ipv4_udp.{hh,cc} — M8 encapsulation + checksums; ipv4udp-file:// sink in gw/sink.cc; protocol/lct_rfc5651_word0.yaml + gw --prepend-lct-word0 (+ optional BE32 --lct-include-tsi / --lct-include-toi / both) (RFC 5651 LCT ahead of ingress inside ALP); gw --prepend-mmtp-word0 (--mmtp-payload-type, --mmtp-packet-id) for MMTP word-0 before optional LCT",
                            "protocol/mmtp_header_word0.yaml — word 0; ts_psn; counter32 (C=1); mmtp_header_extension.yaml (X); mmtp_payload_isobmff_prefix.yaml; mmtp_payload_isobmff_du_length16.yaml; du_header_{timed,non_timed}.yaml; mmtp_payload_gfd_header.yaml (type 0x01)",
                            "M9: lls_table6_1.hh + tools/m9_lls_pack.py + fixtures/lls/minimal_slt.xml",
                        ]}
                    />
                    <BulletGroup
                        title="Test harness"
                        items={[
                            "Per-protocol fixture round-trip tests (auto-generated)",
                            "tools/smoke/codec_smoke.py — pure-Python golden checks (43 cases)",
                            "scripts/integration_test.sh — gw + mmt_probe loopback in 1 process",
                            "scripts/udp_integration_test.sh — same payloads via udp:// + Python UDP concat",
                            "scripts/ipv4udp_file_integration_test.sh — ipv4udp-file:// + m8 strip + verify",
                            "scripts/stltp_integration_test.sh — stltp:// lab UDP strip + verify",
                            "scripts/lls_integration_test.sh — lls:// Table 6.1 + gzip UDP validate",
                            "scripts/rtcm_integration_test.sh — rtcm-gen → gw → verify --validate-rtcm",
                            "scripts/run_all_integration.sh — sink/LLS/STLTP + admin + M7 + LCT word‑0 + RTCM 12×96",
                            "scripts/lct_word0_integration_test.sh — A/B/C: word‑0 · TSI · TOI + mmt_probe verify --strip-lct-word0 [--expect-lct-tsi|--expect-lct-toi]",
                            "scripts/admin_patch_config_integration_test.sh — POST /config/sink sink_uri hot-swap",
                            "scripts/m7_operator_integration_test.sh — bearer + PATCH /services + POST /ingest service_id + --services-state-file",
                            ".github/workflows/ci.yml — Python lint + codegen + codec_smoke + webapp npm build (no Docker); C++/integration: make build && make integ* locally; workflow_dispatch",
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
                                    <Text as="span" weight="semibold">
                                        POST /ingest
                                    </Text>
                                    ,{" "}
                                    <Text as="span" weight="semibold">
                                        GET /config
                                    </Text>
                                    ,{" "}
                                    <Text as="span" weight="semibold">
                                        POST /config/sink
                                    </Text>
                                    {" / "}
                                    <Text as="span" weight="semibold">
                                        PATCH
                                    </Text>
                                    {" / "}
                                    <Text as="span" weight="semibold">
                                        PUT /config
                                    </Text>
                                    {" "}
                                    (sink_uri hot-swap),{" "}
                                    <Text as="span" weight="semibold">
                                        GET / POST / PATCH / DELETE /services
                                    </Text>
                                    , optional Bearer + PEM HTTPS, optional{" "}
                                    <Text as="span" weight="semibold">
                                        --services-state-file
                                    </Text>
                                    , optional M8{" "}
                                    <Text as="span" weight="semibold">
                                        --prepend-lct-word0
                                    </Text>
                                    {" + "}
                                    <Text as="span" weight="semibold">
                                        --lct-codepoint
                                    </Text>
                                    {" "}
                                    (optional BE32 RFC fields:{" "}
                                    <Text as="span" weight="semibold">
                                        --lct-include-tsi
                                    </Text>
                                    {" + "}
                                    <Text as="span" weight="semibold">
                                        --lct-tsi
                                    </Text>
                                    {", "}
                                    <Text as="span" weight="semibold">
                                        --lct-include-toi
                                    </Text>
                                    {" + "}
                                    <Text as="span" weight="semibold">
                                        --lct-toi
                                    </Text>
                                    {", or both for TSI then TOI; "}
                                    RFC&nbsp;5651 word‑0 + lab extensions inside ALP; max user 2035 / 2039 / 2043 octets by prefix size; GET /config echoes LCT fields), plus health/metrics routes when you pass{" "}
                                    <Text as="span" weight="semibold">
                                        --admin-http host:port
                                    </Text>
                                    . Ingest JSON envelope:
                                </Text>
                                <Text size="small">
                                    {`{ "service_id": 1, "type": "rtcm" | "raw" | "lls", "payload_b64": "..." }`}
                                </Text>
                                <Text>
                                    If{" "}
                                    <Text as="span" weight="semibold">
                                        service_id
                                    </Text>{" "}
                                    is set, it must match GET /services; per-row sink_uri routes HTTP
                                    ingest only (TCP keeps --sink). With{" "}
                                    <Text as="span" weight="semibold">
                                        --sink lls://…
                                    </Text>
                                    , cleartext or pre-gzipped LLS is framed per A/331 (Table 6.1 +
                                    gzip) on UDP and skips ALP/TLV; otherwise the same encoder as TCP
                                    ingress applies (`type` is validated only for now).
                                </Text>
                            </Stack>
                        </CardBody>
                    </Card>
                    <Card>
                        <CardHeader>Smallest output surface</CardHeader>
                        <CardBody>
                            <Stack gap={8}>
                                <Text>
                                    Implemented sink:{" "}
                                    <Text as="span" weight="semibold">
                                        stltp://host:port
                                    </Text>{" "}
                                    wraps each TLV-mux frame in a minimal lab STLTP-style UDP
                                    packet (BBP stub, hard-coded L1B/L1D, monotonic timestamps, no
                                    PTP). Not full M10 conformance, but useful on the bench.
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
