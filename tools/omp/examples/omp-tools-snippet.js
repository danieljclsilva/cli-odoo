// OMP wiring example for the cli-odoo Odoo broker (copy, do not load in place).
//
// 1. Copy odoo-broker.js into .omp/tools/ (the loader scans .omp/tools/ for
//    factory modules), e.g. .omp/tools/odoo-broker.js. The module exports
//    the CustomToolFactory directly: module.exports = (pi) => [...tools].
// 2. Serve the broker (`agent serve`), mint a session (`agent grant`), and
//    export ODOO_BROKER_URL + ODOO_BROKER_TOKEN in the OMP process env.
//    Never write the token into this file.
//
// Codex MCP config snippet (restricted: typed broker tools only, token via
// env var, no secrets written):
//   codex mcp add odoo-broker -- \
//     cli-odoo-agent-mcp --url "$ODOO_BROKER_URL"   # stdio adapter
module.exports = {};
