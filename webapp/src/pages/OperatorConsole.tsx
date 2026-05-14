import { useCallback, useState } from "react";
import {
    Card,
    CardBody,
    CardHeader,
    Divider,
    Grid,
    H1,
    H2,
    Row,
    Stack,
    Text,
} from "../canvas-primitives";

const PROXY_PREFIX = "/__atsc3_admin";

function adminPath(path: string): string {
    if (import.meta.env.DEV) {
        return `${PROXY_PREFIX}${path.startsWith("/") ? path : "/" + path}`;
    }
    return path;
}

async function adminFetch(
    path: string,
    bearerToken: string,
    init?: RequestInit,
): Promise<{ ok: boolean; status: number; body: string }> {
    const url = adminPath(path);
    const hdr: Record<string, string> = {
        Accept: "application/json, text/plain;q=0.9, */*;q=0.8",
        ...(init?.headers as Record<string, string>),
    };
    const t = bearerToken.trim();
    if (t) {
        hdr.Authorization = `Bearer ${t}`;
    }
    const r = await fetch(url, {
        ...init,
        headers: hdr,
    });
    const body = await r.text();
    return { ok: r.ok, status: r.status, body };
}

export default function OperatorConsole() {
    const [sinkUri, setSinkUri] = useState("null://");
    const [svcName, setSvcName] = useState("demo");
    const [svcSinkUri, setSvcSinkUri] = useState("");
    const [svcId, setSvcId] = useState("1");
    const [bearerToken, setBearerToken] = useState("");
    const [out, setOut] = useState("");
    const [busy, setBusy] = useState(false);

    const run = useCallback(async (label: string, fn: () => Promise<string>) => {
        setBusy(true);
        setOut(`… ${label}`);
        try {
            setOut(await fn());
        } catch (e) {
            setOut(String(e));
        } finally {
            setBusy(false);
        }
    }, []);

    const prodBlock = !import.meta.env.DEV;

    return (
        <Stack gap={20}>
            <Stack gap={8}>
                <H1>Operator console (M7)</H1>
                <Text tone="secondary">
                    Thin control-plane UI for <code className="mono-inline">atsc3_gw</code>{" "}
                    <strong>--admin-http</strong>. In dev, requests go through the Vite proxy{" "}
                    <code className="mono-inline">{PROXY_PREFIX}</code> →{" "}
                    <code className="mono-inline">ATSC3_ADMIN_URL</code> (default{" "}
                    <code className="mono-inline">http://127.0.0.1:8080</code>). If the gateway
                    uses <code className="mono-inline">--admin-bearer-token</code>, paste the same
                    value under Bearer below.
                </Text>
                {prodBlock && (
                    <Text tone="secondary" weight="semibold">
                        GitHub Pages build: open this app via{" "}
                        <code className="mono-inline">npm run dev</code> with a local gateway, or
                        use <code className="mono-inline">tools/atsc3ctl.py</code> from the shell.
                    </Text>
                )}
            </Stack>

            <Grid columns={2} gap={12}>
                <Card>
                    <CardHeader>Read</CardHeader>
                    <CardBody>
                        <Stack gap={10}>
                            <Row gap={8} wrap>
                                <button
                                    type="button"
                                    className="btn"
                                    disabled={busy || prodBlock}
                                    onClick={() =>
                                        void run("GET /config", async () => {
                                            const r = await adminFetch("/config", bearerToken);
                                            return `${r.status}\n${r.body}`;
                                        })
                                    }
                                >
                                    GET /config
                                </button>
                                <button
                                    type="button"
                                    className="btn"
                                    disabled={busy || prodBlock}
                                    onClick={() =>
                                        void run("GET /services", async () => {
                                            const r = await adminFetch("/services", bearerToken);
                                            return `${r.status}\n${r.body}`;
                                        })
                                    }
                                >
                                    GET /services
                                </button>
                                <button
                                    type="button"
                                    className="btn"
                                    disabled={busy || prodBlock}
                                    onClick={() =>
                                        void run("health", async () => {
                                            const a = await adminFetch("/healthz", bearerToken);
                                            const b = await adminFetch("/readyz", bearerToken);
                                            return `${a.status} healthz\n${a.body}\n${b.status} readyz\n${b.body}`;
                                        })
                                    }
                                >
                                    healthz + readyz
                                </button>
                                <button
                                    type="button"
                                    className="btn"
                                    disabled={busy || prodBlock}
                                    onClick={() =>
                                        void run("GET /metrics", async () => {
                                            const r = await adminFetch("/metrics", bearerToken, {
                                                headers: { Accept: "text/plain" },
                                            });
                                            return `${r.status}\n${r.body}`;
                                        })
                                    }
                                >
                                    GET /metrics
                                </button>
                            </Row>
                        </Stack>
                    </CardBody>
                </Card>

                <Card>
                    <CardHeader>Write</CardHeader>
                    <CardBody>
                        <Stack gap={12}>
                            <label className="field">
                                <span className="field__label">
                                    Bearer token (optional, matches gw --admin-bearer-token)
                                </span>
                                <input
                                    className="field__input"
                                    type="password"
                                    autoComplete="off"
                                    value={bearerToken}
                                    onChange={(e) => setBearerToken(e.target.value)}
                                    disabled={busy || prodBlock}
                                    placeholder=""
                                />
                            </label>
                            <Divider />
                            <label className="field">
                                <span className="field__label">Sink URI (POST /config/sink)</span>
                                <input
                                    className="field__input"
                                    value={sinkUri}
                                    onChange={(e) => setSinkUri(e.target.value)}
                                    disabled={busy || prodBlock}
                                />
                            </label>
                            <button
                                type="button"
                                className="btn btn--primary"
                                disabled={busy || prodBlock}
                                onClick={() =>
                                    void run("POST /config/sink", async () => {
                                        const r = await adminFetch("/config/sink", bearerToken, {
                                            method: "POST",
                                            headers: { "Content-Type": "application/json" },
                                            body: JSON.stringify({ sink_uri: sinkUri }),
                                        });
                                        return `${r.status}\n${r.body}`;
                                    })
                                }
                            >
                                Apply sink
                            </button>
                            <Divider />
                            <label className="field">
                                <span className="field__label">Service name (POST /services)</span>
                                <input
                                    className="field__input"
                                    value={svcName}
                                    onChange={(e) => setSvcName(e.target.value)}
                                    disabled={busy || prodBlock}
                                />
                            </label>
                            <label className="field">
                                <span className="field__label">
                                    Optional sink_uri for this service (POST /ingest + service id)
                                </span>
                                <input
                                    className="field__input"
                                    value={svcSinkUri}
                                    onChange={(e) => setSvcSinkUri(e.target.value)}
                                    disabled={busy || prodBlock}
                                    placeholder="empty = use default gw sink"
                                />
                            </label>
                            <button
                                type="button"
                                className="btn"
                                disabled={busy || prodBlock}
                                onClick={() =>
                                    void run("POST /services", async () => {
                                        const body: { name: string; sink_uri?: string } = {
                                            name: svcName,
                                        };
                                        if (svcSinkUri.trim().length > 0) {
                                            body.sink_uri = svcSinkUri.trim();
                                        }
                                        const r = await adminFetch("/services", bearerToken, {
                                            method: "POST",
                                            headers: { "Content-Type": "application/json" },
                                            body: JSON.stringify(body),
                                        });
                                        return `${r.status}\n${r.body}`;
                                    })
                                }
                            >
                                Add service
                            </button>
                            <label className="field">
                                <span className="field__label">
                                    Service id (DELETE / PATCH sink)
                                </span>
                                <input
                                    className="field__input"
                                    value={svcId}
                                    onChange={(e) => setSvcId(e.target.value)}
                                    disabled={busy || prodBlock}
                                />
                            </label>
                            <Row gap={8} wrap>
                                <button
                                    type="button"
                                    className="btn"
                                    disabled={busy || prodBlock}
                                    onClick={() =>
                                        void run("PATCH clear service sink_uri", async () => {
                                            const r = await adminFetch(
                                                `/services?id=${encodeURIComponent(svcId)}`,
                                                bearerToken,
                                                {
                                                    method: "PATCH",
                                                    headers: {
                                                        "Content-Type": "application/json",
                                                    },
                                                    body: JSON.stringify({ sink_uri: null }),
                                                },
                                            );
                                            return `${r.status}\n${r.body}`;
                                        })
                                    }
                                >
                                    PATCH clear sink routing
                                </button>
                                <button
                                    type="button"
                                    className="btn btn--danger"
                                    disabled={busy || prodBlock}
                                    onClick={() =>
                                        void run("DELETE /services", async () => {
                                            const r = await adminFetch(
                                                `/services?id=${encodeURIComponent(svcId)}`,
                                                bearerToken,
                                                { method: "DELETE" },
                                            );
                                            return `${r.status}\n${r.body}`;
                                        })
                                    }
                                >
                                    Delete service
                                </button>
                            </Row>
                        </Stack>
                    </CardBody>
                </Card>
            </Grid>

            <Card>
                <CardHeader>Output</CardHeader>
                <CardBody>
                    <pre className="mono-pre">{out || "—"}</pre>
                </CardBody>
            </Card>

            <H2>CLI</H2>
            <Text tone="secondary" size="small">
                Same surface via{" "}
                <code className="mono-inline">python3 tools/atsc3ctl.py --help</code>: set{" "}
                <code className="mono-inline">ATSC3_ADMIN</code>, and{" "}
                <code className="mono-inline">ATSC3_ADMIN_TOKEN</code> when the gw uses bearer
                auth.
            </Text>
        </Stack>
    );
}
