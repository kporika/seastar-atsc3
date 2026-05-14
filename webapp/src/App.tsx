import { useState } from "react";
import EndToEndGaps from "./pages/EndToEndGaps";
import OperatorConsole from "./pages/OperatorConsole";

type AppPage = "gaps" | "operator";

export default function App() {
    const [page, setPage] = useState<AppPage>("gaps");

    return (
        <div className="app-shell">
            <header className="app-header">
                <a
                    className="app-header__brand"
                    href="https://github.com/kporika/seastar-atsc3"
                    target="_blank"
                    rel="noreferrer"
                >
                    <span className="app-header__logo" aria-hidden>
                        3.0
                    </span>
                    <span className="app-header__title">seastar-atsc3</span>
                    <span className="app-header__sub">
                        {page === "gaps" ? "end-to-end gap analysis" : "operator console (M7)"}
                    </span>
                </a>
                <nav className="app-header__tabs" aria-label="Primary">
                    <button
                        type="button"
                        className={`app-header__tab${page === "gaps" ? " app-header__tab--active" : ""}`}
                        onClick={() => setPage("gaps")}
                    >
                        Gap analysis
                    </button>
                    <button
                        type="button"
                        className={`app-header__tab${page === "operator" ? " app-header__tab--active" : ""}`}
                        onClick={() => setPage("operator")}
                    >
                        Operator
                    </button>
                </nav>
                <nav className="app-header__nav">
                    <a
                        href="https://github.com/kporika/seastar-atsc3"
                        target="_blank"
                        rel="noreferrer"
                    >
                        repo
                    </a>
                    <a
                        href="https://github.com/kporika/seastar-atsc3/blob/main/docs/END_TO_END_GAPS.md"
                        target="_blank"
                        rel="noreferrer"
                    >
                        markdown
                    </a>
                </nav>
            </header>
            <main className="app-main">
                {page === "gaps" ? <EndToEndGaps /> : <OperatorConsole />}
            </main>
            <footer className="app-footer">
                <span>
                    Apache 2.0 ·{" "}
                    <a
                        href="https://github.com/kporika/seastar-atsc3"
                        target="_blank"
                        rel="noreferrer"
                    >
                        kporika/seastar-atsc3
                    </a>
                </span>
                <span className="app-footer__sub">
                    Rendered from{" "}
                    <code>docs/end_to_end_gaps.canvas.tsx</code>
                </span>
            </footer>
        </div>
    );
}
