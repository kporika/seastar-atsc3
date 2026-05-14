import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves project sites under /<repo>/, so every asset URL must
// be prefixed accordingly. The deploy URL is
//   https://kporika.github.io/seastar-atsc3/
// Override BASE_URL via env when previewing under a different prefix
// (e.g. an actions preview deploy or a Cloudflare Pages mirror).
const repoBase = process.env.BASE_URL ?? "/seastar-atsc3/";
const adminTarget = process.env.ATSC3_ADMIN_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
    base: repoBase,
    plugins: [react()],
    server: {
        proxy: {
            "/__atsc3_admin": {
                target: adminTarget,
                changeOrigin: true,
                rewrite: (p) => {
                    const stripped = p.replace(/^\/__atsc3_admin/, "");
                    return stripped.length > 0 ? stripped : "/";
                },
            },
        },
    },
    build: {
        // Inlining the small bundle keeps the page < 200 kB total and dodges
        // round trips on first paint. Override if the bundle grows past ~10 kB.
        assetsInlineLimit: 8192,
        sourcemap: true,
        target: "es2022",
    },
});
