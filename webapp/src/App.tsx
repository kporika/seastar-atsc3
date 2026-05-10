import EndToEndGaps from "./pages/EndToEndGaps";

export default function App() {
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
                    <span className="app-header__sub">end-to-end gap analysis</span>
                </a>
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
                <EndToEndGaps />
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
