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
    init?: RequestInit,
): Promise<{ ok: boolean; status: number; body: string }> {
    const url = adminPath(path);
    const r = await fetch(url, {
        ...init,
        headers: {
            Accept: "application/json, text/plain;q=0.9, */*;q=0.8",
            ...(init?.headers as Record<string, string>),
        },
    });
    const body = await r.text();
    return { ok: r.ok, status: r.status, body };
}

export default function OperatorConsole() {
    const [sinkUri, setSinkUri] = useState("null://");
    const [svcName, setSvcName] = useState("demo");
    const [svcId, setSvcId] = useState("1");
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
                    <code className="mono-inline">http://127.0.0.1:8080</code>).
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
                                            const r = await adminFetch("/config");
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
                                            const r = await adminFetch("/services");
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
                                            const a = await adminFetch("/healthz");
                                            const b = await adminFetch("/readyz");
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
                                            const r = await adminFetch("/metrics", {
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
                                        const r = await adminFetch("/config/sink", {
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
                            <button
                                type="button"
                                className="btn"
                                disabled={busy || prodBlock}
                                onClick={() =>
                                    void run("POST /services", async () => {
                                        const r = await adminFetch("/services", {
                                            method: "POST",
                                            headers: { "Content-Type": "application/json" },
                                            body: JSON.stringify({ name: svcName }),
                                        });
                                        return `${r.status}\n${r.body}`;
                                    })
                                }
                            >
                                Add service
                            </button>
                            <label className="field">
                                <span className="field__label">Service id (DELETE)</span>
                                <input
                                    className="field__input"
                                    value={svcId}
                                    onChange={(e) => setSvcId(e.target.value)}
                                    disabled={busy || prodBlock}
                                />
                            </label>
                            <button
                                type="button"
                                className="btn btn--danger"
                                disabled={busy || prodBlock}
                                onClick={() =>
                                    void run("DELETE /services", async () => {
                                        const r = await adminFetch(
                                            `/services?id=${encodeURIComponent(svcId)}`,
                                            { method: "DELETE" },
                                        );
                                        return `${r.status}\n${r.body}`;
                                    })
                                }
                            >
                                Delete service
                            </button>
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
                Same surface from the repo:{" "}
                <code className="mono-inline">python3 tools/atsc3ctl.py --help</code> (or{" "}
                <code className="mono-inline">ATSC3_ADMIN=http://127.0.0.1:8080</code>).
            </Text>
        </Stack>
    );
}
