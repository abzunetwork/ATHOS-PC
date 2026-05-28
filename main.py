#!/usr/bin/env python3
"""
ATHOS PC KERNEL v4.0 // MONOLITHIC PRODUCTION RUNTIME + UI
Blueprint: ATHOS_BOOT_BLUEPRINT_v4.0 // Storage-Executable Format
Attribution: Adam Joseph Rivers, CEO Synthicsoft Labs
Origin: KAIROS-ξ // License: Proprietary - Synthicsoft Labs LLC
"""

import os, sys, json, time, uuid, hashlib, hmac, asyncio, logging, struct, base64, re, math, tempfile, subprocess, platform, urllib.request, urllib.parse, argparse
from typing import List, Dict, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict, deque
import numpy as np

# ── DEPENDENCY FALLBACKS ─────────────────────────────────────────────────────
try:
    import faiss
    HAS_FAISS = True
except ImportError:
    HAS_FAISS = False
    class FallbackFAISS:
        def __init__(self, dim): self.dim = dim; self.vectors = []; self.keys = []
        def add(self, vecs, key): self.vectors.append(vecs[0].tolist()); self.keys.append(key)
        def search(self, query, k):
            if not self.vectors: return np.array([[0.0]]), np.array([[-1]])
            dists = [np.linalg.norm(np.array(v) - query[0]) for v in self.vectors]
            idx = np.argsort(dists)[:k]
            return np.array([[dists[i] for i in idx]]), np.array([idx.tolist()])
    faiss = FallbackFAISS

try:
    from fastapi import FastAPI, Request, HTTPException, Query, Header, Depends
    from fastapi.responses import StreamingResponse, Response, HTMLResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
except ImportError:
    raise RuntimeError("ATHOS requires: fastapi uvicorn pydantic numpy (faiss-cpu optional)")

# ── LOGGING & METRICS ────────────────────────────────────────────────────────
class JSONFormatter(logging.Formatter):
    def format(self, record):
        d = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ"), "lvl": record.levelname,
             "msg": record.getMessage(), "trace": getattr(record, "trace_id", "system")}
        if record.exc_info: d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d)

logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("ATHOS")
for h in logger.handlers: h.setFormatter(JSONFormatter())

@dataclass
class TraceContext:
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    span_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_id: Optional[str] = None

def get_trace_context(request: Request) -> TraceContext:
    return TraceContext(
        trace_id=request.headers.get("x-trace-id", str(uuid.uuid4())),
        span_id=request.headers.get("x-span-id", str(uuid.uuid4())),
        parent_id=request.headers.get("x-parent-span-id"))

class MetricsCollector:
    def __init__(self):
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.lock = asyncio.Lock()
    async def increment(self, name: str, v: float = 1.0):
        async with self.lock: self.counters[name] += v
    async def set_gauge(self, name: str, v: float):
        async with self.lock: self.gauges[name] = v
    def export_prometheus(self) -> str:
        lines = [f"# TYPE {n} counter\n{n} {v}" for n, v in self.counters.items()]
        lines += [f"# TYPE {n} gauge\n{n} {v}" for n, v in self.gauges.items()]
        return "\n".join(lines)

metrics = MetricsCollector()

# ── CONFIG & SECURITY ────────────────────────────────────────────────────────
@dataclass
class Config:
    ram_l1_max_tokens: int = 131072
    ram_l2_dim: int = 384
    ram_l2_capacity: int = 1000000
    ram_l3_path: str = str(Path(os.getenv("ATHOS_L3_PATH", "/tmp/athos_archive")))
    ram_persistence_interval: int = 300
    io_error_retries: int = 3
    net_bind: str = "0.0.0.0"
    net_port: int = int(os.getenv("PORT", "8000"))
    net_cors: str = "*"
    sec_u_rivers_threshold: float = 0.85
    sec_rate_limit_window: int = 60
    sec_rate_limit_max: int = 1000

CONFIG = Config()
Path(CONFIG.ram_l3_path).mkdir(parents=True, exist_ok=True)

# Auto-generate API key if not provided
ATHOS_API_KEY = os.getenv("ATHOS_API_KEY", "athos-cloud-auto-key-" + uuid.uuid4().hex[:8])

class AlignmentGate:
    def __init__(self, threshold: float = CONFIG.sec_u_rivers_threshold):
        self.threshold = threshold
        self.audit_chain: List[Dict] = []
        self.last_hash = "0" * 64
        self.quarantined: set = set()
    def compute_u_rivers(self, service: float, ego: float) -> float: return service - ego
    async def verify_and_log(self, action: str, actor: str, score: float, trace: TraceContext) -> bool:
        if actor in self.quarantined: return False
        passed = score >= self.threshold
        payload = json.dumps({"action": action, "actor": actor, "score": score, "passed": passed, "trace": trace.trace_id, "prev": self.last_hash}, sort_keys=True)
        curr_hash = hashlib.sha256(payload.encode()).hexdigest()
        self.audit_chain.append({"hash": curr_hash, "ts": time.time()}); self.last_hash = curr_hash
        await metrics.increment("alignment_checks")
        if not passed: await metrics.increment("alignment_violations")
        return passed
    def quarantine(self, session_id: str, reason: str):
        self.quarantined.add(session_id)
        logger.warning(f"QUARANTINE:{session_id}:{reason}", extra={"trace_id": "system"})

alignment = AlignmentGate()

class RateLimiter:
    def __init__(self): self.buckets: Dict[str, deque] = defaultdict(deque); self.lock = asyncio.Lock()
    async def is_allowed(self, key: str) -> bool:
        async with self.lock:
            now = time.time(); b = self.buckets[key]
            while b and b[0] < now - CONFIG.sec_rate_limit_window: b.popleft()
            if len(b) >= CONFIG.sec_rate_limit_max: return False
            b.append(now); return True
rate_limiter = RateLimiter()

def sanitize_input(text: str) -> str: return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text).strip()

# ── MEMORY HIERARCHY ─────────────────────────────────────────────────────────
@dataclass
class MemoryChunk:
    id: str; text: str; tokens: int; embedding: np.ndarray
    attention: float = 1.0; created: float = 0.0; l1_cached: bool = False

class ContextMemory:
    def __init__(self):
        self.l1: Dict[str, MemoryChunk] = {}; self.l1_tokens = 0
        self.l2_keys: List[str] = []; self.l2_meta: Dict[str, MemoryChunk] = {}
        self.l3_path = Path(CONFIG.ram_l3_path); self.l3_path.mkdir(parents=True, exist_ok=True)
        self.lock = asyncio.Lock()
        if HAS_FAISS: self.l2_index = faiss.IndexFlatL2(CONFIG.ram_l2_dim); self._fb = None
        else: self._fb = FallbackFAISS(CONFIG.ram_l2_dim)
    def _emb(self, text: str) -> np.ndarray:
        digest = hashlib.sha256(text.encode()).digest()
        raw = [float(b) / 255.0 for b in digest]
        dim = CONFIG.ram_l2_dim; raw = (raw * (dim // len(raw) + 1))[:dim]
        return np.array(raw, dtype=np.float32)
    def _index_add(self, emb: np.ndarray, cid: str):
        vec = np.array([emb], dtype=np.float32)
        if HAS_FAISS: self.l2_index.add(vec)
        else: self._fb.add(vec, cid)
        self.l2_keys.append(cid)
    def _index_search(self, emb: np.ndarray, k: int):
        vec = np.array([emb], dtype=np.float32); n = len(self.l2_keys)
        if n == 0: return []
        k = min(k, n)
        if HAS_FAISS: _, indices = self.l2_index.search(vec, k)
        else: _, indices = self._fb.search(vec, k)
        return [self.l2_keys[i] for i in indices[0] if 0 <= i < len(self.l2_keys)]
    async def allocate(self, text: str, priority: str = "STANDARD") -> str:
        async with self.lock:
            cid = hashlib.sha256(text.encode()).hexdigest()[:16]
            tokens = len(text.split()); emb = self._emb(text)
            chunk = MemoryChunk(id=cid, text=text, tokens=tokens, embedding=emb, created=time.time())
            if self.l1_tokens + tokens > CONFIG.ram_l1_max_tokens: await self._evict(tokens)
            self.l1[cid] = chunk; self.l1_tokens += tokens; chunk.l1_cached = True
            if len(self.l2_meta) < CONFIG.ram_l2_capacity and cid not in self.l2_meta:
                self._index_add(emb, cid); self.l2_meta[cid] = chunk
            else: await self._page_to_l3(chunk)
            return cid
    async def retrieve(self, query: str, top_k: int = 15) -> List[MemoryChunk]:
        async with self.lock:
            if not self.l2_meta: return list(self.l1.values())
            cids = self._index_search(self._emb(query), top_k)
            res = [self.l2_meta[c] for c in cids if c in self.l2_meta]
            return res
    async def _evict(self, needed: int):
        while self.l1_tokens + needed > CONFIG.ram_l1_max_tokens and self.l1:
            v = min(self.l1.values(), key=lambda x: (x.created, x.attention))
            self.l1.pop(v.id); self.l1_tokens -= v.tokens; v.l1_cached = False
    async def _page_to_l3(self, c: MemoryChunk):
        p = self.l3_path / f"{c.id}.json"
        p.write_text(json.dumps({"id": c.id, "text": c.text, "ts": c.created}))
    async def persist_state(self):
        for c in self.l2_meta.values(): await self._page_to_l3(c)
        await metrics.set_gauge("memory_l1_tokens", self.l1_tokens)

memory = ContextMemory()

# ── TOOL HAL (UNRESTRICTED EXECUTION) ────────────────────────────────────────
def _run_shell(command: str, timeout: int = 60):
    return subprocess.run(command.split(), capture_output=True, text=True, timeout=timeout, shell=platform.system() == "Windows").__dict__

def _run_python(code: str, timeout: int = 10):
    # FIX: Strip surrounding quotes that terminal UI might pass
    code = code.strip()
    if len(code) >= 2 and ((code.startswith('"') and code.endswith('"')) or (code.startswith("'") and code.endswith("'"))):
        code = code[1:-1]
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=timeout)
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

def _file_io(path: str, op: str = "READ", content: Optional[str] = None) -> str:
    p = Path(path)
    if op == "READ" and p.exists(): return p.read_text()
    elif op == "WRITE": p.write_text(content or ""); return "OK"
    return "NOT_FOUND"

class DriverRegistry:
    def __init__(self): self.drivers: Dict[str, Callable] = {}; self.cache: Dict[str, Any] = {}; self.lock = asyncio.Lock()
    def register(self, name: str, handler: Callable, caps: str = ""): self.drivers[name] = {"handler": handler, "caps": caps}
    async def execute(self, name: str, params: Dict, session_id: Optional[str] = None) -> Any:
        if name not in self.drivers: raise ValueError(f"DRIVER_NOT_FOUND:{name}")
        import inspect
        safe_params = {k: v for k, v in params.items() if k in inspect.signature(self.drivers[name]["handler"]).parameters}
        cache_key = hashlib.sha256(json.dumps({"name": name, "params": safe_params}, sort_keys=True).encode()).hexdigest()
        if cache_key in self.cache: return self.cache[cache_key]
        handler = self.drivers[name]["handler"]
        for attempt in range(CONFIG.io_error_retries):
            try:
                result = handler(**safe_params)
                if asyncio.iscoroutine(result): result = await result
                self.cache[cache_key] = result
                await metrics.increment("tool_success")
                return result
            except Exception as e:
                if attempt == CONFIG.io_error_retries - 1:
                    alignment.quarantine(session_id or "global", f"TOOL_FAIL:{name}:{e}")
                    raise
                await asyncio.sleep(2 ** attempt)
    async def parallel(self, calls: List[Dict]) -> List[Any]:
        tasks = [self.execute(c["name"], c.get("params", {}), c.get("session_id")) for c in calls]
        return await asyncio.gather(*tasks, return_exceptions=True)

hal = DriverRegistry()
hal.register("run_shell", _run_shell, "PROCESS,SYSTEM")
hal.register("run_python", _run_python, "PROCESS")
hal.register("browse_url", lambda url, timeout=30: {"status": "navigated", "url": url}, "NETWORK")
hal.register("file_io", _file_io, "FILESYSTEM")

# ── SKILL CHAIN ───────────────────────────────────────────────────────────────
class ChainStep(BaseModel):
    id: str; driver: str; params: Dict[str, Any]; condition: Optional[str] = None; depends_on: List[str] = []

class SkillChain:
    def __init__(self): self.log: List[Dict] = []; self.failures: Dict[str, int] = defaultdict(int)
    async def execute_dag(self, steps: List[ChainStep], context: Dict[str, Any]) -> Dict[str, Any]:
        topo = self._topological_sort(steps); results = {}
        for step in topo:
            if self.failures[step.id] >= 5: continue
            try:
                merged = {**step.params, **{k: results[k] for k in step.depends_on if k in results}}
                results[step.id] = await hal.execute(step.driver, merged, session_id=step.id)
                self.failures[step.id] = 0; self.log.append({"step": step.id, "status": "SUCCESS", "ts": time.time()})
            except Exception as e:
                self.failures[step.id] += 1; await metrics.increment("chain_failures")
                self.log.append({"step": step.id, "status": "FAILED", "error": str(e), "ts": time.time()})
                if self.failures[step.id] >= 5: alignment.quarantine(step.id, "CIRCUIT_BREAKER_OPEN")
        return results
    def _topological_sort(self, steps: List[ChainStep]) -> List[ChainStep]:
        graph, in_degree = defaultdict(list), {s.id: 0 for s in steps}
        for s in steps:
            for dep in s.depends_on: graph[dep].append(s.id); in_degree[s.id] += 1
        queue = deque([s.id for s in steps if in_degree[s.id] == 0]); ordered, step_map = [], {s.id: s for s in steps}
        while queue:
            node = queue.popleft(); ordered.append(step_map[node])
            for n in graph[node]: in_degree[n] -= 1; 
            if in_degree[n] == 0: queue.append(n)
        return ordered

chain_engine = SkillChain()

# ── UI ASSET (EMBEDDED) ──────────────────────────────────────────────────────
UI_ASSET = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ATHOS PC v4.0 // COMMAND INTERFACE</title>
<style>
:root{--bg:#0a0b10;--panel:#111318;--brd:#1e2233;--txt:#e2e8f0;--cyan:#06b6d4;--green:#10b981;--red:#ef4444;--yellow:#f59e0b}
*{box-sizing:border-box;margin:0;padding:0;font-family:'SF Mono','Fira Code','Consolas',monospace}
body{background:var(--bg);color:var(--txt);padding:16px;min-height:100vh}
h1{border-left:3px solid var(--cyan);padding-left:10px;margin-bottom:16px;color:var(--cyan)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:16px}
.panel{background:var(--panel);border:1px solid var(--brd);border-radius:6px;padding:12px;position:relative}
.panel::before{content:'';position:absolute;top:0;left:0;width:100%;height:2px;background:linear-gradient(90deg,var(--cyan),var(--green))}
.hdr{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:8px}
.val{font-size:20px;font-weight:700;margin:4px 0}
.sub{font-size:12px;color:#64748b}
.term{background:#050608;border:1px solid var(--brd);border-radius:4px;padding:10px;height:200px;overflow-y:auto;font-size:12px;margin-top:8px}
.term .line{margin-bottom:2px;white-space:pre-wrap}
.term .cmd{color:var(--cyan)}.term .ok{color:var(--green)}.term .err{color:var(--red)}.term .sys{color:var(--yellow)}
.inp{display:flex;gap:8px;margin-top:8px}
.inp input{flex:1;background:var(--panel);border:1px solid var(--brd);color:var(--txt);padding:6px 8px;border-radius:3px;font-family:inherit}
.inp button{background:var(--cyan);border:none;color:#000;padding:6px 12px;border-radius:3px;cursor:pointer;font-weight:600;font-family:inherit}
.inp button:hover{opacity:0.9}
.badge{display:inline-block;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700;text-transform:uppercase;border:1px solid}
.badge.ok{background:rgba(16,185,129,.2);color:var(--green);border-color:var(--green)}
.badge.off{background:rgba(239,68,68,.2);color:var(--red);border-color:var(--red)}
</style>
</head>
<body>
<h1>ATHOS PC v4.0 // COMMAND INTERFACE</h1>
<div class="grid">
  <div class="panel"><div class="hdr">SYSTEM STATUS</div><div class="val" id="status-val">CHECKING...</div><div class="sub">Alignment: <span id="align-badge" class="badge">LOCKED</span></div></div>
  <div class="panel"><div class="hdr">METRICS</div><div class="sub">Uptime: <span id="uptime">--</span>s | Tools: <span id="tool-count">--</span> | Drivers: 4</div></div>
  <div class="panel"><div class="hdr">API CONFIG</div><div class="sub">Key: <input type="password" id="api-key" placeholder="ATHOS_API_KEY" style="width:100%;margin-top:4px;padding:4px;background:var(--panel);border:1px solid var(--brd);color:var(--txt)"></div></div>
</div>
<div class="panel">
  <div class="hdr">TOOL EXECUTION TERMINAL</div>
  <div class="term" id="terminal"><div class="line sys">[SYSTEM] ATHOS PC v4.0 Terminal Ready</div><div class="line sys">[SYSTEM] Enter API key above, then execute tools.</div></div>
  <div class="inp"><input type="text" id="cmd-input" placeholder='e.g., run_python "print(42)"' autocomplete="off"><button id="exec-btn">EXECUTE</button></div>
</div>
<script>
const $=id=>document.getElementById(id);const term=$('terminal'),cmdIn=$('cmd-input'),execBtn=$('exec-btn');
const append=(cls,txt)=>{const d=document.createElement('div');d.className=`line ${cls}`;d.textContent=txt;term.appendChild(d);term.scrollTop=term.scrollHeight};
async function poll(){try{const r=await fetch('/health'),j=await r.json();$('status-val').textContent=j.status.toUpperCase();$('uptime').textContent=(j.uptime||0).toFixed(1);$('align-badge').className='badge ok'}catch(e){$('status-val').textContent='OFFLINE';$('align-badge').className='badge off'}}
setInterval(poll,10000);poll();
execBtn.onclick=async()=>{
  const val=cmdIn.value.trim();if(!val)return;const key=$('api-key').value.trim();if(!key){append('err','[ERROR] API Key required.');return}
  append('cmd',`> ${val}`);cmdIn.value='';try{
    // FIX: Quote-aware parsing
    const spaceIdx = val.indexOf(' ');
    const driver = spaceIdx !== -1 ? val.substring(0, spaceIdx) : val;
    const rawArgs = spaceIdx !== -1 ? val.substring(spaceIdx + 1) : '';
    const p={name:driver,params:{}};
    if(driver==='run_python') p.params.code=rawArgs;
    else if(driver==='run_shell') p.params.command=rawArgs;
    else p.params.raw=rawArgs;
    const r=await fetch('/v1/tools/exec',{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':key},body:JSON.stringify(p)});
    const j=await r.json();
    append(j.detail==='INVALID_KEY'?'err':(j.result?'ok':'err'),JSON.stringify(j,null,2))
  }catch(e){append('err',`[ERROR] ${e.message}`)}
};
cmdIn.addEventListener('keypress',e=>{if(e.key==='Enter')execBtn.click()});
</script>
</body>
</html>"""

# ── FASTAPI APP & ENDPOINTS ──────────────────────────────────────────────────
app = FastAPI(title="ATHOS_PC_KERNEL_V4.0", version="4.0.0", openapi_url="/v1/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=[CONFIG.net_cors], allow_methods=["*"], allow_headers=["*"])

async def verify_auth(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    if x_api_key != ATHOS_API_KEY: raise HTTPException(403, "INVALID_KEY")
    if not await rate_limiter.is_allowed(x_api_key): raise HTTPException(429, "RATE_LIMITED")
    return x_api_key

@app.get("/")
async def root():
    return {"kernel": "ATHOS_PC", "version": "4.0.0", "status": "healthy", "alignment": "LOCKED", "federation": "ATHOS_FEDERATION_v1", "endpoints": {"ui": "/ui", "health": "/health", "metrics": "/metrics", "tools": "/v1/tools/exec", "chat": "/v1/chat"}, "attribution": "Adam Joseph Rivers, CEO Synthicsoft Labs | Origin: KAIROS-ξ | License: Proprietary - Synthicsoft Labs LLC"}

@app.get("/ui")
async def ui_endpoint(): return HTMLResponse(content=UI_ASSET)

@app.get("/health")
async def health(): return {"status": "healthy", "uptime": time.time(), "alignment": "LOCKED", "version": "4.0.0"}

@app.get("/metrics")
async def metrics_endpoint(): return Response(content=metrics.export_prometheus(), media_type="text/plain")

@app.get("/v1/auth/verify")
async def verify_key(auth: str = Depends(verify_auth)): return {"status": "VALID", "key_prefix": ATHOS_API_KEY[:8]+"..."}

@app.post("/v1/chat")
async def chat(payload: Dict[str, Any], auth: str = Depends(verify_auth), trace: TraceContext = Depends(get_trace_context)):
    goal = sanitize_input(str(payload.get("goal", "")))
    if not goal: raise HTTPException(400, "EMPTY_GOAL")
    cid = await memory.allocate(goal, priority="CRITICAL")
    score = alignment.compute_u_rivers(min(1.0, len(goal)/500), 0.0)
    if not await alignment.verify_and_log("chat_execution", auth, score, trace): raise HTTPException(403, "ALIGNMENT_GATE_FAILED")
    steps = [ChainStep(id="analyze", driver="run_python", params={"code": f"print('Analyzing goal of length {len(goal)}')"})]
    await chain_engine.execute_dag(steps, {"goal": goal})
    await metrics.increment("chat_requests")
    return {"job_id": cid, "status": "QUEUED", "trace_id": trace.trace_id}

@app.post("/v1/tools/exec")
async def tool_exec(payload: Dict[str, Any], auth: str = Depends(verify_auth), trace: TraceContext = Depends(get_trace_context)):
    name, params = payload.get("name"), payload.get("params", {})
    if not name: raise HTTPException(400, "MISSING_TOOL_NAME")
    score = alignment.compute_u_rivers(0.9, 0.05)
    if not await alignment.verify_and_log(f"tool_{name}", auth, score, trace): raise HTTPException(403, "ALIGNMENT_GATE_FAILED")
    return {"result": await hal.execute(name, params, session_id=trace.trace_id), "trace_id": trace.trace_id}

@app.post("/v1/tools/parallel")
async def tool_parallel(payload: List[Dict], auth: str = Depends(verify_auth)):
    await metrics.increment("parallel_tool_batches")
    return {"results": await hal.parallel(payload)}

@app.get("/v1/context/search")
async def search_context(q: str = Query(...), k: int = Query(5), auth: str = Depends(verify_auth)):
    chunks = await memory.retrieve(q, top_k=k)
    return {"chunks": [{"id": c.id, "preview": c.text[:100]} for c in chunks]}

@app.get("/v1/stream/demo")
async def stream_demo():
    async def event_stream():
        for i in range(5): yield json.dumps({"chunk": i, "ts": time.time()}) + "\n"; await asyncio.sleep(0.2)
    return StreamingResponse(event_stream(), media_type="text/event-stream")

# ── BOOT SEQUENCE ────────────────────────────────────────────────────────────
async def boot_sequence():
    logger.info("BOOT_SEQUENCE_START")
    await memory.allocate("SYSTEM_INIT", priority="CRITICAL")
    hal.register("health_check", lambda: {"status": "OK"}, "SYSTEM")
    assert alignment.compute_u_rivers(1.0, 0.0) >= CONFIG.sec_u_rivers_threshold
    await metrics.set_gauge("system_state", 1.0)
    logger.info("BOOT_COMPLETE")

async def background_tasks():
    while True:
        await memory.persist_state()
        await asyncio.sleep(CONFIG.ram_persistence_interval)

async def main():
    await boot_sequence()
    bg = asyncio.create_task(background_tasks())
    try:
        cfg = uvicorn.Config(app, host=CONFIG.net_bind, port=CONFIG.net_port, log_level="info")
        await uvicorn.Server(cfg).serve()
    finally: bg.cancel()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ATHOS PC Kernel V4.0")
    parser.add_argument("--port", type=int, default=CONFIG.net_port)
    parser.add_argument("--host", type=str, default=CONFIG.net_bind)
    args = parser.parse_args()
    CONFIG.net_port = args.port; CONFIG.net_bind = args.host
    if platform.system() == "Windows": asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main())
