/*
 * Re-implementation of the small slice of the Cursor `cursor/canvas` runtime
 * that the docs/end_to_end_gaps.canvas.tsx file consumes. We keep the same
 * component names + prop shapes so the page module is a near-verbatim copy
 * of the canvas source, modulo the import line.
 *
 * Everything renders to plain divs/spans and pulls colors from the CSS custom
 * properties defined in index.css. No third-party UI library.
 */

import type { CSSProperties, ReactNode } from "react";

// -----------------------------------------------------------------------------
// Tone tokens — mapped to the .pill--*, .row-tone--*, .stat--*, .callout--*
// modifier classes in index.css.
// -----------------------------------------------------------------------------

export type PillTone = "neutral" | "success" | "warning" | "danger" | "info";
export type RowTone = "success" | "warning" | "danger" | "info";
export type StatTone = "default" | "success" | "warning" | "danger" | "info";
export type CalloutTone = "info";

/** The canvas template uses "deleted" as the danger pill tone; keep both. */
type LegacyPillTone = PillTone | "deleted";

function pillToneClass(tone: LegacyPillTone | undefined): string {
    switch (tone) {
        case "success":
            return "pill--success";
        case "warning":
            return "pill--warning";
        case "danger":
        case "deleted":
            return "pill--danger";
        case "info":
            return "pill--info";
        default:
            return "";
    }
}

// -----------------------------------------------------------------------------
// Layout: Stack / Row / Grid
// -----------------------------------------------------------------------------

type StackProps = {
    gap?: number;
    children: ReactNode;
    style?: CSSProperties;
};

export function Stack({ gap = 8, children, style }: StackProps) {
    return (
        <div className="stack" style={{ gap, ...style }}>
            {children}
        </div>
    );
}

type RowProps = {
    gap?: number;
    align?: "start" | "center" | "end" | "stretch";
    wrap?: boolean;
    children: ReactNode;
    style?: CSSProperties;
};

export function Row({
    gap = 8,
    align = "stretch",
    wrap = false,
    children,
    style,
}: RowProps) {
    const alignItems =
        align === "start"
            ? "flex-start"
            : align === "end"
              ? "flex-end"
              : align === "center"
                ? "center"
                : "stretch";
    return (
        <div
            className={`row${wrap ? " row--wrap" : ""}`}
            style={{ gap, alignItems, ...style }}
        >
            {children}
        </div>
    );
}

type GridProps = {
    columns: number;
    gap?: number;
    children: ReactNode;
    style?: CSSProperties;
};

export function Grid({ columns, gap = 12, children, style }: GridProps) {
    return (
        <div
            className="grid"
            style={{
                gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`,
                gap,
                ...style,
            }}
        >
            {children}
        </div>
    );
}

// -----------------------------------------------------------------------------
// Typography: H1/H2/H3 + Text
// -----------------------------------------------------------------------------

export function H1({ children }: { children: ReactNode }) {
    return <h1 className="h1">{children}</h1>;
}

export function H2({ children }: { children: ReactNode }) {
    return <h2 className="h2">{children}</h2>;
}

export function H3({ children }: { children: ReactNode }) {
    return <h3 className="h3">{children}</h3>;
}

type TextProps = {
    tone?: "default" | "secondary" | "tertiary";
    size?: "default" | "small";
    weight?: "regular" | "semibold";
    as?: "p" | "span" | "div";
    children: ReactNode;
};

export function Text({
    tone = "default",
    size = "default",
    weight = "regular",
    as = "p",
    children,
}: TextProps) {
    const cls = [
        "text",
        tone === "secondary" && "text--secondary",
        tone === "tertiary" && "text--tertiary",
        size === "small" && "text--small",
        weight === "semibold" && "text--semibold",
    ]
        .filter(Boolean)
        .join(" ");
    if (as === "span") {
        return <span className={cls}>{children}</span>;
    }
    if (as === "div") {
        return <div className={cls}>{children}</div>;
    }
    return <p className={cls}>{children}</p>;
}

// -----------------------------------------------------------------------------
// Divider
// -----------------------------------------------------------------------------

export function Divider() {
    return <hr className="divider" />;
}

// -----------------------------------------------------------------------------
// Card
// -----------------------------------------------------------------------------

type CardProps = { children: ReactNode };

export function Card({ children }: CardProps) {
    return <section className="card">{children}</section>;
}

type CardHeaderProps = {
    trailing?: ReactNode;
    children: ReactNode;
};

export function CardHeader({ trailing, children }: CardHeaderProps) {
    return (
        <header className="card__header">
            <span>{children}</span>
            {trailing && <span>{trailing}</span>}
        </header>
    );
}

export function CardBody({ children }: { children: ReactNode }) {
    return <div className="card__body">{children}</div>;
}

// -----------------------------------------------------------------------------
// Pill
// -----------------------------------------------------------------------------

type PillProps = {
    tone?: LegacyPillTone;
    size?: "sm" | "md";
    children: ReactNode;
};

export function Pill({ tone, size = "md", children }: PillProps) {
    const cls = ["pill", size === "md" && "pill--lg", pillToneClass(tone)]
        .filter(Boolean)
        .join(" ");
    return <span className={cls}>{children}</span>;
}

// -----------------------------------------------------------------------------
// Stat
// -----------------------------------------------------------------------------

type StatProps = {
    value: ReactNode;
    label: string;
    tone?: StatTone;
};

export function Stat({ value, label, tone = "default" }: StatProps) {
    const toneCls =
        tone === "default" ? "" : ` stat--${tone}`;
    return (
        <div className={`stat${toneCls}`}>
            <div className="stat__value">{value}</div>
            <div className="stat__label">{label}</div>
        </div>
    );
}

// -----------------------------------------------------------------------------
// Callout
// -----------------------------------------------------------------------------

type CalloutProps = {
    tone?: CalloutTone;
    title?: string;
    children: ReactNode;
};

export function Callout({ tone = "info", title, children }: CalloutProps) {
    return (
        <div className={`callout callout--${tone}`}>
            {title && <div className="callout__title">{title}</div>}
            <div>{children}</div>
        </div>
    );
}

// -----------------------------------------------------------------------------
// Table
// -----------------------------------------------------------------------------

type TableProps = {
    headers: string[];
    rows: ReactNode[][];
    rowTone?: RowTone[];
    columnAlign?: ("left" | "right" | "center")[];
    striped?: boolean;
    stickyHeader?: boolean;
};

export function Table({
    headers,
    rows,
    rowTone,
    columnAlign,
    striped = false,
}: TableProps) {
    const tableCls = ["table", striped && "table--striped"]
        .filter(Boolean)
        .join(" ");
    return (
        <div className="table-wrap">
            <table className={tableCls}>
                <thead>
                    <tr>
                        {headers.map((h, i) => (
                            <th
                                key={h}
                                style={{
                                    textAlign: columnAlign?.[i] ?? "left",
                                }}
                            >
                                {h}
                            </th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {rows.map((cols, rIdx) => {
                        const tone = rowTone?.[rIdx];
                        const trCls = tone ? `row-tone--${tone}` : undefined;
                        return (
                            <tr key={rIdx} className={trCls}>
                                {cols.map((c, cIdx) => (
                                    <td
                                        key={cIdx}
                                        style={{
                                            textAlign:
                                                columnAlign?.[cIdx] ?? "left",
                                        }}
                                    >
                                        {c}
                                    </td>
                                ))}
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}

// -----------------------------------------------------------------------------
// useHostTheme — the canvas reads color tokens off this; here we just expose
// the same shape backed by the CSS custom properties we ship in index.css.
// -----------------------------------------------------------------------------

type HostTheme = {
    stroke: { tertiary: string };
    fill: { tertiary: string };
};

export function useHostTheme(): HostTheme {
    return {
        stroke: { tertiary: "var(--stroke-subtle)" },
        fill: { tertiary: "var(--stroke-strong)" },
    };
}
