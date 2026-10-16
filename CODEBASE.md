# Codebase guide

The HTTP/WebSocket server is JavaScript ESM under server/. The UI is React/TypeScript under src/. This localization foundation changes only frontend presentation and test/build support; server collectors, APIs and stored records retain their behavior.

src/i18n/index.ts owns one bundled i18next/react-i18next loader. src/locales/en/ is the authoritative source and fallback; zh-CN catalogs mirror page namespaces. Settings is the first translated page. The selector persists a browser-local preference and updates HTML language without saving server settings. Raw server diagnostics stay unchanged. See [the contributor guide](docs/i18n.md) for scope, dependencies and future namespaces.

npm test checks statically wired translation keys against English catalogs, runs the checker's positive/negative fixtures, then the server and frontend suites. The checker uses the existing Vite/Rolldown parser, not an added parser dependency. Component and i18n tests verify same-mount switching, fallback, ordinary interpolation/plurals, blocked storage and preserved settings payloads. Also run typecheck and production build. Native collector tests require Linux/POSIX utilities; isolate device actions with fixtures.
