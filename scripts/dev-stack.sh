#!/usr/bin/env bash
# Ripar local dev stack: the whole Ripar stack on a LOCAL anvil fork of Monad testnet (chain id 10143).
#
#   scripts/dev-stack.sh [up] [options]    start it (foreground: Ctrl-C stops everything; --detach: leave it running)
#   scripts/dev-stack.sh down [--work DIR] stop what a detached `up` started
#   scripts/dev-stack.sh status            what is running, and where
#   scripts/dev-stack.sh e2e [options]     up --detach, node scripts/e2e.mjs against it, down (always)
#
# What `up` does:
#   1. anvil --fork-url https://testnet-rpc.monad.xyz --chain-id 10143 on 127.0.0.1:8545 (--port to change it);
#   2. refreshes a PRIVATE copy of contracts/ (src, script, foundry.toml, remappings.txt; lib/ is a read-only
#      directory junction / symlink to contracts/lib) under <work>/contracts and runs
#      `forge script script/Deploy.s.sol --broadcast` THERE (never inside contracts/ itself), with anvil's dev key #0
#      and RIPAR_WORKFLOW_OWNER = anvil account #9 (the CRE workflow owner the sentinel checks);
#   3. writes the deployments JSON where the agent and the companion read it:
#        <work>/deployments/10143.json          (the agent's DEPLOYMENTS)
#        companion/public/devstack/10143.json    (served by the companion dev server at /devstack/10143.json)
#        companion/public/devstack/stack.json    (the whole stack: RPC, agent URL, courier; see <work>/stack.json)
#   4. funds accounts: a FRESH agent key (cast wallet new; anvil's dev accounts carry EIP-7702 code on Monad testnet,
#      so ERC-721 mints to them revert) gets 1000 MON with anvil_setBalance; anvil's dev accounts (the companion's
#      "anvil" courier is account #0) keep anvil's 10000 MON;
#   5. registers the agent in the forked ERC-8004 IdentityRegistry (agent/scripts/register-erc8004.ts --broadcast)
#      and starts the agent service (agent/src/main.ts) on 127.0.0.1:8787 with that AGENT_ID and a fresh data dir;
#   6. starts the companion dev server (Vite) on 127.0.0.1:5173 unless --no-companion, and prints its URL.
#
# Options: --port N (anvil, 8545)  --agent-port N (8787)  --companion-port N (5173)  --no-companion  --detach
#          --work DIR (F:/tmp/ripar-devstack, else $TMPDIR/ripar-devstack)  --fork-url URL (or RIPAR_FORK_URL)
#          --fork-block N  --contracts-rev REV (deploy contracts/ as committed at REV via `git archive`, e.g. HEAD,
#          instead of the working tree, e.g. while someone is editing it)
#
# Safety: every transaction goes to the local anvil only. The keys used are anvil's public dev key #0 (deployer) and a
# key generated here for the agent (kept in <work>/agent.env, never printed). Nothing is sent to a public chain.
# Never `rm -rf <work>` by hand: <work>/contracts/lib is a junction to contracts/lib.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
REPO_N="$(native "$REPO")"

ANVIL_KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil dev account #0 (public test key)
ANVIL_ACCOUNT0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
ANVIL_ACCOUNT9=0xa0Ee7A142d267C1f36714E4a8F75612F20a79720
CHAIN_ID=10143

CMD=up
case "${1:-}" in
  up | down | status | e2e) CMD=$1; shift ;;
  -h | --help) sed -n '2,33p' "${BASH_SOURCE[0]}"; exit 0 ;;
esac

PORT=8545
AGENT_PORT=8787
COMPANION_PORT=5173
COMPANION=1
DETACH=0
FORK_URL="${RIPAR_FORK_URL:-https://testnet-rpc.monad.xyz}"
FORK_BLOCK=""
CONTRACTS_REV=""
if [ -d /f/tmp ]; then WORK=/f/tmp/ripar-devstack; else WORK="${TMPDIR:-/tmp}/ripar-devstack"; fi
E2E_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT=$2; shift 2 ;;
    --agent-port) AGENT_PORT=$2; shift 2 ;;
    --companion-port) COMPANION_PORT=$2; shift 2 ;;
    --no-companion) COMPANION=0; shift ;;
    --with-companion) COMPANION=2; shift ;;
    --detach) DETACH=1; shift ;;
    --work) WORK=$2; shift 2 ;;
    --fork-url) FORK_URL=$2; shift 2 ;;
    --fork-block) FORK_BLOCK=$2; shift 2 ;;
    --contracts-rev) CONTRACTS_REV=$2; shift 2 ;;
    --) shift; E2E_ARGS=("$@"); break ;;
    *) echo "dev-stack: unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
done
# e2e needs no companion dev server unless asked (--with-companion)
if [ "$CMD" = e2e ] && [ "$COMPANION" = 1 ]; then COMPANION=0; fi
[ "$COMPANION" = 2 ] && COMPANION=1
WORK_N="$(native "$WORK")"
RUN="$WORK/run"
LOGS="$WORK/logs"
PUBLIC_DIR="$REPO/companion/public/devstack"

for d in /f/tools/foundry "${HOME:-}/.foundry/bin"; do [ -d "$d" ] && PATH="$d:$PATH"; done
export PATH
export npm_config_cache="${npm_config_cache:-F:/tools/npm-cache}"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

say() { printf '[dev-stack] %s\n' "$*"; }
die() { printf '[dev-stack] ERROR: %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------------------------------------------ processes
alive() { # name
  local f="$RUN/$1.pid"
  [ -f "$f" ] || return 1
  local pid; pid=$(cat "$f")
  if [ -f "$RUN/$1.winpid" ] && command -v tasklist >/dev/null 2>&1; then
    tasklist //FI "PID eq $(cat "$RUN/$1.winpid")" 2>/dev/null | grep -q "$(cat "$RUN/$1.winpid")"
  else
    kill -0 "$pid" 2>/dev/null
  fi
}

start_bg() { # name logfile dir envfile|- cmd...   (the env file is sourced, so no secret is on a command line)
  local name=$1 log=$2 dir=$3 envf=$4; shift 4
  (cd "$dir" && if [ "$envf" != - ]; then set -a && . "$envf" && set +a; fi && exec "$@") >"$log" 2>&1 &
  local pid=$!
  echo "$pid" >"$RUN/$name.pid"
  if [ -r "/proc/$pid/winpid" ]; then cat "/proc/$pid/winpid" >"$RUN/$name.winpid"; fi
}

stop_one() { # name
  local name=$1 f="$RUN/$1.pid"
  [ -f "$f" ] || return 0
  local pid; pid=$(cat "$f")
  if [ -f "$RUN/$name.winpid" ] && command -v taskkill >/dev/null 2>&1; then
    taskkill //F //T //PID "$(cat "$RUN/$name.winpid")" >/dev/null 2>&1 || true
  fi
  kill "$pid" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$f" "$RUN/$name.winpid"
  say "stopped $name"
}

stop_all() {
  for n in companion agent anvil; do stop_one "$n"; done
  rm -f "$PUBLIC_DIR/10143.json" "$PUBLIC_DIR/stack.json" "$WORK/stack.json"
  rmdir "$PUBLIC_DIR" 2>/dev/null || true
}

# free = nothing answers a connect (curl exit 7: refused; Windows takes ~2 s to say so) and 127.0.0.1:<port> binds
port_free() {
  curl -s -o /dev/null --max-time 6 "http://127.0.0.1:$1/"
  [ $? -eq 7 ] || return 1
  node -e 'const s=require("net").createServer();s.once("error",()=>process.exit(1));s.listen(+process.argv[1],"127.0.0.1",()=>s.close(()=>process.exit(0)))' "$1"
}

rpc() { # method params-json
  curl -s --max-time 30 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "http://127.0.0.1:$PORT"
}

wait_for() { # what seconds cmd...
  local what=$1 secs=$2; shift 2
  local t=0
  until "$@" >/dev/null 2>&1; do
    t=$((t + 1))
    [ $t -ge $((secs * 2)) ] && return 1
    sleep 0.5
  done
  say "$what is up"
}

tail_log() { [ -f "$1" ] && { echo "---- last lines of $1"; tail -n 40 "$1"; echo "----"; } >&2; }

# ------------------------------------------------------------------------------------------------ status / down
if [ "$CMD" = status ]; then
  for n in anvil agent companion; do
    if alive "$n"; then say "$n: running (pid $(cat "$RUN/$n.pid"))"; else say "$n: not running"; fi
  done
  [ -f "$WORK/stack.json" ] && cat "$WORK/stack.json"
  exit 0
fi
if [ "$CMD" = down ]; then
  stop_all
  exit 0
fi

# ------------------------------------------------------------------------------------------------ up
for tool in node anvil forge cast curl; do command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"; done
mkdir -p "$RUN" "$LOGS"
for n in anvil agent companion; do alive "$n" && die "a stack is already running from $WORK ($n): run 'scripts/dev-stack.sh down' first"; done
rm -f "$RUN"/*.pid "$RUN"/*.winpid
port_free "$PORT" || die "port $PORT is in use (anvil): pass --port"
port_free "$AGENT_PORT" || die "port $AGENT_PORT is in use (agent): pass --agent-port"
[ "$COMPANION" = 1 ] && { port_free "$COMPANION_PORT" || die "port $COMPANION_PORT is in use (companion): pass --companion-port or --no-companion"; }

STARTED=0
on_exit() {
  local code=$?
  if [ "$STARTED" = 0 ] || [ "$DETACH" = 0 ]; then
    if [ "$code" -eq 130 ]; then say "interrupted: stopping"; elif [ "$code" -ne 0 ]; then say "stopping after an error (exit $code)"; fi
    stop_all
  fi
}
trap on_exit EXIT
trap 'exit 130' INT TERM

RPC_URL="http://127.0.0.1:$PORT"

# 1. anvil fork
ANVIL_ARGS=(--fork-url "$FORK_URL" --chain-id "$CHAIN_ID" --host 127.0.0.1 --port "$PORT" --retries 8 --timeout 60000)
[ -n "$FORK_BLOCK" ] && ANVIL_ARGS+=(--fork-block-number "$FORK_BLOCK")
say "anvil fork of $FORK_URL on $RPC_URL (chain id $CHAIN_ID)"
start_bg anvil "$LOGS/anvil.log" "$WORK" - anvil "${ANVIL_ARGS[@]}"
chain_ok() { rpc eth_chainId '[]' | grep -q '"result":"0x279f"'; }
wait_for anvil 120 chain_ok || { tail_log "$LOGS/anvil.log"; die "anvil did not start"; }
FORKED_AT=$(cast block-number --rpc-url "$RPC_URL")

# 2. the private copy of contracts/ and the deployment
CDIR="$WORK/contracts"
mkdir -p "$CDIR"
rm -rf "$CDIR/src" "$CDIR/script" # real copies only (lib is a junction: never deleted)
if [ -n "$CONTRACTS_REV" ]; then
  say "contracts: $CONTRACTS_REV (git archive) -> $CDIR"
  git -C "$REPO" archive "$CONTRACTS_REV" contracts/src contracts/script contracts/foundry.toml contracts/remappings.txt |
    tar -x -C "$WORK" || die "git archive $CONTRACTS_REV failed"
else
  say "contracts: working tree -> $CDIR"
  cp -r "$REPO/contracts/src" "$REPO/contracts/script" "$CDIR/" || die "copy of contracts/ failed"
  cp "$REPO/contracts/foundry.toml" "$REPO/contracts/remappings.txt" "$CDIR/"
fi
if [ ! -e "$CDIR/lib/forge-std" ]; then
  if command -v cmd >/dev/null 2>&1; then
    cmd //c mklink //J "$(cygpath -w "$CDIR/lib")" "$(cygpath -w "$REPO/contracts/lib")" >/dev/null || die "mklink /J failed"
  else
    ln -s "$REPO/contracts/lib" "$CDIR/lib" || die "ln -s failed"
  fi
fi
rm -f "$CDIR/deployments/$CHAIN_ID.json"
say "forge script script/Deploy.s.sol --broadcast (deployer = anvil #0, RIPAR_WORKFLOW_OWNER = anvil #9)"
(cd "$CDIR" && RIPAR_WORKFLOW_OWNER=$ANVIL_ACCOUNT9 forge script script/Deploy.s.sol \
  --rpc-url "$RPC_URL" --broadcast --private-key "$ANVIL_KEY0") >"$LOGS/forge.log" 2>&1 ||
  { tail_log "$LOGS/forge.log"; die "forge script failed"; }
[ -f "$CDIR/deployments/$CHAIN_ID.json" ] || { tail_log "$LOGS/forge.log"; die "no deployments/$CHAIN_ID.json"; }
mkdir -p "$WORK/deployments" "$PUBLIC_DIR"
cp "$CDIR/deployments/$CHAIN_ID.json" "$WORK/deployments/$CHAIN_ID.json"
cp "$CDIR/deployments/$CHAIN_ID.json" "$PUBLIC_DIR/$CHAIN_ID.json"
DEPLOYMENTS_N="$WORK_N/deployments/$CHAIN_ID.json"
jget() { node -e "const j=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));process.stdout.write(String(j[process.argv[2]]))" "$DEPLOYMENTS_N" "$1"; }
for k in RiparDeviceRegistry PulseCosignEnforcer RiparSentinel RiparReputationRelay MockUSD; do
  a=$(jget "$k")
  code=$(cast code "$a" --rpc-url "$RPC_URL")
  [ ${#code} -gt 4 ] || die "$k $a has no code on the fork"
  say "  $k $a"
done

# 3. the agent: a fresh key, funded, registered in ERC-8004, then the service
KEYOUT=$(cast wallet new) || die "cast wallet new failed"
AGENT_KEY=$(printf '%s\n' "$KEYOUT" | sed -n 's/^Private key: *//p')
AGENT_ADDRESS=$(printf '%s\n' "$KEYOUT" | sed -n 's/^Address: *//p')
[ -n "$AGENT_KEY" ] && [ -n "$AGENT_ADDRESS" ] || die "could not parse cast wallet new"
unset KEYOUT
rpc anvil_setBalance "[\"$AGENT_ADDRESS\",\"0x3635C9ADC5DEA00000\"]" | grep -q '"result"' || die "anvil_setBalance failed"
say "agent $AGENT_ADDRESS funded with 1000 MON (key in $WORK_N/agent.env, not printed)"
rm -rf "$WORK/agent-data" # a plain directory this script owns: every stack starts with a fresh agent
mkdir -p "$WORK/agent-data"
COMPANION_ORIGINS="http://127.0.0.1:$COMPANION_PORT,http://localhost:$COMPANION_PORT"
umask 077
cat >"$WORK/agent.env" <<EOF
RPC_URL=$RPC_URL
CHAIN_ID=$CHAIN_ID
DEPLOYMENTS=$DEPLOYMENTS_N
AGENT_SIGNER=local
AGENT_PRIVATE_KEY=$AGENT_KEY
DATA_DIR=$WORK_N/agent-data
HOST=127.0.0.1
PORT=$AGENT_PORT
COMPANION_ORIGIN=$COMPANION_ORIGINS
AUTO_RUN_SECONDS=0
EOF
umask 022
unset AGENT_KEY
AGENT_RUN=(node --conditions=ripar-source --import tsx)
say "registering the agent in the forked ERC-8004 IdentityRegistry"
REG=$(cd "$REPO/agent" && set -a && . "$WORK/agent.env" && set +a && "${AGENT_RUN[@]}" scripts/register-erc8004.ts --broadcast 2>&1)
printf '%s\n' "$REG" >"$LOGS/register-erc8004.log"
AGENT_ID=$(printf '%s\n' "$REG" | sed -n 's/^registered: agentId \([0-9]*\).*/\1/p')
if [ -n "$AGENT_ID" ]; then
  echo "AGENT_ID=$AGENT_ID" >>"$WORK/agent.env"
  say "agentId $AGENT_ID"
else
  say "WARNING: ERC-8004 registration failed (see $LOGS/register-erc8004.log); the agent runs without AGENT_ID"
fi
say "agent service on http://127.0.0.1:$AGENT_PORT"
start_bg agent "$LOGS/agent.log" "$REPO/agent" "$WORK/agent.env" "${AGENT_RUN[@]}" src/main.ts
health_ok() { curl -s --max-time 2 "http://127.0.0.1:$AGENT_PORT/health" | grep -q '"ok":true'; }
wait_for agent 60 health_ok || { tail_log "$LOGS/agent.log"; die "the agent did not start"; }

# 4. the companion dev server
COMPANION_URL=""
if [ "$COMPANION" = 1 ]; then
  say "companion dev server on http://127.0.0.1:$COMPANION_PORT (open http://127.0.0.1:$COMPANION_PORT/?devstack)"
  start_bg companion "$LOGS/companion.log" "$REPO/companion" - node "$REPO_N/node_modules/vite/bin/vite.js" \
    --host 127.0.0.1 --port "$COMPANION_PORT" --strictPort
  vite_ok() { curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$COMPANION_PORT/devstack/$CHAIN_ID.json" | grep -q 200; }
  wait_for companion 90 vite_ok || { tail_log "$LOGS/companion.log"; die "the companion dev server did not start"; }
  COMPANION_URL="http://127.0.0.1:$COMPANION_PORT/"
fi

# 5. the stack description (for scripts/e2e.mjs and the companion's ?devstack)
PIDS="$(for n in anvil agent companion; do [ -f "$RUN/$n.pid" ] && printf '%s=%s ' "$n" "$(cat "$RUN/$n.pid")"; done)"
S_WORK="$WORK_N" S_CHAIN="$CHAIN_ID" S_RPC="$RPC_URL" S_FORK="$FORK_URL" S_BLOCK="$FORKED_AT" \
  S_DEP="$DEPLOYMENTS_N" S_DEPURL="devstack/$CHAIN_ID.json" S_AGENT_URL="http://127.0.0.1:$AGENT_PORT" \
  S_AGENT="$AGENT_ADDRESS" S_AGENT_ID="${AGENT_ID:-}" S_COMPANION="$COMPANION_URL" S_ORIGINS="$COMPANION_ORIGINS" \
  S_COURIER="$ANVIL_ACCOUNT0" S_OWNER="$ANVIL_ACCOUNT9" S_PIDS="$PIDS" node -e '
const fs = require("fs");
const e = process.env;
const dep = JSON.parse(fs.readFileSync(e.S_DEP, "utf8"));
const pids = Object.fromEntries(e.S_PIDS.trim().split(/\s+/).filter(Boolean).map((kv) => { const [k, v] = kv.split("="); return [k, Number(v)]; }));
const pub = {
  version: 1,
  startedAt: new Date().toISOString(),
  chainId: Number(e.S_CHAIN),
  rpcUrl: e.S_RPC,
  forkUrl: e.S_FORK,
  forkedAtBlock: Number(e.S_BLOCK),
  companionDeploymentsUrl: "/" + e.S_DEPURL, // no leading slash in the env: MSYS would rewrite it as a path
  agentUrl: e.S_AGENT_URL,
  agentAddress: e.S_AGENT,
  agentId: e.S_AGENT_ID || null,
  companionUrl: e.S_COMPANION || null,
  companionOrigins: e.S_ORIGINS,
  courier: e.S_COURIER,
  workflowOwner: e.S_OWNER,
  creForwarder: dep.creForwarder,
  deployments: dep,
};
fs.writeFileSync(process.argv[1], JSON.stringify({ ...pub, work: e.S_WORK, deploymentsPath: e.S_DEP, pids }, null, 2) + String.fromCharCode(10));
fs.writeFileSync(process.argv[2], JSON.stringify(pub, null, 2) + String.fromCharCode(10));
' "$WORK_N/stack.json" "$(native "$PUBLIC_DIR")/stack.json" || die "could not write stack.json"
FORWARDER=$(jget creForwarder)
STARTED=1
if [ -n "$COMPANION_URL" ]; then
  COMPANION_LINE="OPEN ${COMPANION_URL}?devstack   (fills in the Connect page: RPC, courier, contracts, agent)"
else
  COMPANION_LINE="not started (--no-companion)"
fi

cat <<EOF

  Ripar dev stack (local anvil fork of Monad testnet, chain $CHAIN_ID, forked at block $FORKED_AT)
    RPC           $RPC_URL
    deployments   $DEPLOYMENTS_N
    agent         http://127.0.0.1:$AGENT_PORT   ($AGENT_ADDRESS, ERC-8004 agentId ${AGENT_ID:-none})
    companion     $COMPANION_LINE
                  by hand instead: Connect "Local anvil fork", RPC $RPC_URL, courier "Anvil dev account"
                  ($ANVIL_ACCOUNT0), deployments URL /devstack/$CHAIN_ID.json, agent http://127.0.0.1:$AGENT_PORT
                  then: Device (EMULATOR) -> Pair -> Vault (deploy, fund) -> Mandate -> Inbox ("Ask the agent to run now")
    CRE forwarder $FORWARDER (impersonate it on the fork to close a lane; workflow owner $ANVIL_ACCOUNT9)
    stack file    $WORK_N/stack.json      logs: $(native "$LOGS")
    end-to-end    node scripts/e2e.mjs --stack $WORK_N/stack.json

EOF

if [ "$CMD" = e2e ]; then
  node "$REPO_N/scripts/e2e.mjs" --stack "$WORK_N/stack.json" ${E2E_ARGS[@]+"${E2E_ARGS[@]}"}
  code=$?
  DETACH=0
  exit $code
fi
if [ "$DETACH" = 1 ]; then
  say "detached: 'scripts/dev-stack.sh down' stops it"
  exit 0
fi
say "running; Ctrl-C stops everything"
while alive anvil && alive agent; do sleep 2; done
say "a process exited"
tail_log "$LOGS/anvil.log"
tail_log "$LOGS/agent.log"
exit 1
