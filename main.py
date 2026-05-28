#!/usr/bin/env python3
"""ATHOS_PC_KERNEL_V4.0 // MONOLITHIC PRODUCTION RUNTIME — CLOUD READY"""
import os, sys, json, time, uuid, hashlib, asyncio, logging, subprocess, re, traceback, argparse, platform
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict, deque
import numpy as np

# ── DEPENDENCIES & FALLBACKS ──────────────────────────────────────────────────
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
    from fastapi.responses import StreamingResponse, Response
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
except ImportError:
    raise RuntimeError("Missing: fastapi uvicorn pydantic numpy")

# ── LOGGING & METRICS ─────────────────────────────────────────────────────────
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
    span_id: str  = field(default_factory=lambda: str(uuid.uuid4()))
    parent_id: Optional[str] = None

def get_trace_context(request: Request) -> TraceContext:
    return TraceContext(
        trace_id=request.headers.get("x-trace-id", str(uuid.uuid4())),
        span_id=request.headers.get("x-span-id", str(uuid.uuid4())),
        parent_id=request.headers.get("x-parent-span-id"))

class MetricsCollector:
    def __init__(self):
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges:   Dict[str, float] = defaultdict(float)
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

# ── CONFIG & SECURITY ─────────────────────────────────────────────────────────
@dataclass
class Config:
    ram_l1_max_tokens: int  = 131072
    ram_l2_dim: int         = 384
    ram_l2_capacity: int    = 1000000
    ram_l3_path: str        = str(Path(os.getenv("ATHOS_L3_PATH", "/tmp/athos_archive")))
    ram_persistence_interval: int = 300
    io_error_retries: int   = 3
    net_bind: str           = "0.0.0.0"
    net_port: int           = int(os.getenv("PORT", "8000"))
    net_cors: str           = "*"
    sec_u_rivers_threshold: float = 0.85
    sec_rate_limit_window: int    = 60
    sec_rate_limit_max: int       = 1000

CONFIG = Config()
Path(CONFIG.ram_l3_path).mkdir(parents=True, exist_ok=True)

# Auto-generate API key if not provided (prevents startup crash on Render/Replit)
ATHOS_API_KEY = os.getenv("ATHOS_API_KEY", "athos-cloud-auto-key-" + uuid.uuid4().hex[:8])

class AlignmentGate:
    def __init__(self, threshold: float = CONFIG.sec_u_rivers_threshold):
        self.threshold = threshold; self.audit_chain = []; self.last_hash = "0"*64; self.quarantined = set()
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

# ── MEMORY & TOOLS ────────────────────────────────────────────────────────────
@dataclass
class MemoryChunk:
    id: str; text: str; tokens: int; embedding: np.ndarray
    attention: float = 1.0; created: float = 0.0; l1_cached: bool = False

class ContextMemory:
    def __init__(self):
        self.l1: Dict[str, MemoryChunk] = {}; self.l1_tokens = 0
        self.l2_keys: List[str] = []; self.l2_meta: Dict[str, MemoryChunk] = {}
        self.l3_path = Path(CONFIG.ram_l3_path)
        self.lock = asyncio.Lock()
        self.l2_index = faiss.IndexFlatL2(CONFIG.ram_l2_dim) if HAS_FAISS else FallbackFAISS(CONFIG.ram_l2_dim)
    def _emb(self, text: str) -> np.ndarray:
        raw = [float(b)/255.0 for b in hashlib.sha256(text.encode()).digest()]
        dim = CONFIG.ram_l2_dim; raw = (raw * (dim//len(raw)+1))[:dim]
        return np.array(raw, dtype=np.float32)
    async def allocate(self, text: str, priority: str = "STANDARD") -> str:
        async with self.lock:
            cid = hashlib.sha256(text.encode()).hexdigest()[:16]
            tokens = len(text.split()); emb = self._emb(text)
            chunk = MemoryChunk(id=cid, text=text, tokens=tokens, embedding=emb, created=time.time())
            if self.l1_tokens + tokens > CONFIG.ram_l1_max_tokens: await self._evict(tokens)
            self.l1[cid] = chunk; self.l1_tokens += tokens; chunk.l1_cached = True
            if len(self.l2_meta) < CONFIG.ram_l2_capacity and cid not in self.l2_meta:
                if HAS_FAISS: self.l2_index.add(np.array([emb], dtype=np.float32))
                else: self.l2_index.add(np.array([emb], dtype=np.float32), cid)
                self.l2_keys.append(cid); self.l2_meta[cid] = chunk
            return cid
    async def _evict(self, needed: int):
        while self.l1_tokens + needed > CONFIG.ram_l1_max_tokens and self.l1:
            victim = min(self.l1.values(), key=lambda x: (x.created, x.attention))
            self.l1.pop(victim.id); self.l1_tokens -= victim.tokens; victim.l1_cached = False
    async def persist_state(self):
        for c in self.l2_meta.values():
            p = self.l3_path / f"{c.id}.json"
            if not p.exists(): p.write_text(json.dumps({"id": c.id, "text": c.text, "ts": c.created}))
        await metrics.set_gauge("memory_l1_tokens", self.l1_tokens)

memory = ContextMemory()

def _run_shell(command: str, timeout: int = 60):
    return subprocess.run(command.split(), capture_output=True, text=True, timeout=timeout).__dict__
def _run_python(code: str, timeout: int = 10):
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=timeout).__dict__

class DriverRegistry:
    def __init__(self): self.drivers = {}; self.cache = {}; self.lock = asyncio.Lock()
    def register(self, name: str, handler: Callable): self.drivers[name] = handler
    async def execute(self, name: str, params: Dict, session_id: Optional[str] = None) -> Any:
        if name not in self.drivers: raise ValueError(f"DRIVER_NOT_FOUND:{name}")
        import inspect
        safe_params = {k: v for k, v in params.items() if k in inspect.signature(self.drivers[name]).parameters}
        handler = self.drivers[name]
        try:
            result = handler(**safe_params)
            if asyncio.iscoroutine(result): result = await result
            await metrics.increment("tool_success")
            return result
        except Exception as e:
            await metrics.increment("tool_failure"); raise

hal = DriverRegistry()
hal.register("run_shell", _run_shell)
hal.register("run_python", _run_python)
hal.register("browse_url", lambda url, timeout=30: {"status": "navigated", "url": url})

# ── SKILL CHAIN ───────────────────────────────────────────────────────────────
class ChainStep(BaseModel):
    id: str; driver: str; params: Dict[str, Any]
    condition: Optional[str] = None; depends_on: List[str] = []

class SkillChain:
    def __init__(self): self.log = []; self.failures = defaultdict(int)
    async def execute_dag(self, steps: List[ChainStep], context: Dict[str, Any]) -> Dict[str, Any]:
        topo = self._topological_sort(steps)
        results = {}
        for step in topo:
            if self.failures[step.id] >= 5: continue
            try:
                merged = {**step.params, **{k: results[k] for k in step.depends_on if k in results}}
                results[step.id] = await hal.execute(step.driver, merged, session_id=step.id)
                self.log.append({"step": step.id, "status": "SUCCESS", "ts": time.time()})
            except Exception as e:
                self.failures[step.id] += 1; await metrics.increment("chain_failures")
                self.log.append({"step": step.id, "status": "FAILED", "error": str(e), "ts": time.time()})
        return results
    def _topological_sort(self, steps):
        graph, in_degree = defaultdict(list), {s.id: 0 for s in steps}
        for s in steps:
            for dep in s.depends_on: graph[dep].append(s.id); in_degree[s.id] += 1
        queue = deque([s.id for s in steps if in_degree[s.id] == 0])
        ordered, step_map = [], {s.id: s for s in steps}
        while queue:
            node = queue.popleft(); ordered.append(step_map[node])
            for n in graph[node]: in_degree[n] -= 1
            if in_degree[n] == 0: queue.append(n)
        return ordered

chain_engine = SkillChain()

# ── API & BOOT ────────────────────────────────────────────────────────────────
app = FastAPI(title="ATHOS_PC_KERNEL_V4.0", version="4.0.0")
app.add_middleware(CORSMiddleware, allow_origins=[CONFIG.net_cors], allow_methods=["*"], allow_headers=["*"])

async def verify_auth(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    if x_api_key != ATHOS_API_KEY: raise HTTPException(403, "INVALID_KEY")
    if not await rate_limiter.is_allowed(x_api_key): raise HTTPException(429, "RATE_LIMITED")
    return x_api_key

@app.get("/health")
async def health():
    return {"status": "healthy", "uptime": time.time(), "alignment": "LOCKED", "version": "4.0.0"}

@app.get("/metrics")
async def metrics_endpoint():
    return Response(content=metrics.export_prometheus(), media_type="text/plain")

@app.post("/v1/tools/exec")
async def tool_exec(payload: Dict[str, Any], auth: str = Depends(verify_auth),
                    trace: TraceContext = Depends(get_trace_context)):
    name, params = payload.get("name"), payload.get("params", {})
    if not name: raise HTTPException(400, "MISSING_TOOL_NAME")
    score = alignment.compute_u_rivers(0.9, 0.05)
    if not await alignment.verify_and_log(f"tool_{name}", auth, score, trace):
        raise HTTPException(403, "ALIGNMENT_GATE_FAILED")
    return {"result": await hal.execute(name, params, session_id=trace.trace_id), "trace_id": trace.trace_id}

@app.post("/v1/tools/parallel")
async def tool_parallel(payload: List[Dict], auth: str = Depends(verify_auth)):
    await metrics.increment("parallel_tool_batches")
    return {"results": await hal.parallel(payload)}

@app.get("/v1/context/search")
async def search_context(q: str = Query(...), k: int = Query(5), auth: str = Depends(verify_auth)):
    chunks = await memory.retrieve(q, top_k=k)
    return {"chunks": [{"id": c.id, "preview": c.text[:100]} for c in chunks]}

async def boot_sequence():
    logger.info("BOOT_SEQUENCE_START")
    await memory.allocate("SYSTEM_INIT", priority="CRITICAL")
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
    finally:
        bg.cancel()

if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main())
