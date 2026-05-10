import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves project sites under /<repo>/, so every asset URL must
// be prefixed accordingly. The deploy URL is
//   https://kporika.github.io/seastar-atsc3/
// Override BASE_URL via env when previewing under a different prefix
// (e.g. an actions preview deploy or a Cloudflare Pages mirror).
const repoBase = process.env.BASE_URL ?? "/seastar-atsc3/";

export default defineConfig({
    base: repoBase,
    plugins: [react()],
    build: {
        // Inlining the small bundle keeps the page < 200 kB total and dodges
        // round trips on first paint. Override if the bundle grows past ~10 kB.
        assetsInlineLimit: 8192,
        sourcemap: true,
        target: "es2022",
    },
});
