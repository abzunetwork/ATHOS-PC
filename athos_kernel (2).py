#!/usr/bin/env python3
"""ATHOS_PC_KERNEL_V3.0 // MONOLITHIC PRODUCTION RUNTIME — FIXED"""
import os, sys, json, time, uuid, hashlib, asyncio, logging, subprocess, re, traceback, argparse, platform
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict, deque
import numpy as np

# ── DEPENDENCIES ──────────────────────────────────────────────────────────────
try:
    import faiss
    HAS_FAISS = True
except ImportError:
    HAS_FAISS = False

class FallbackFAISS:
    def __init__(self, dim): self.dim = dim; self.vectors = []; self.keys = []
    def add(self, vecs, key):
        self.vectors.append(vecs[0].tolist()); self.keys.append(key)
    def search(self, query, k):
        if not self.vectors: return np.array([[0.0]]), np.array([[-1]])
        dists = [np.linalg.norm(np.array(v) - query[0]) for v in self.vectors]
        idx = np.argsort(dists)[:k]
        return np.array([[dists[i] for i in idx]]), np.array([idx.tolist()])

try:
    from fastapi import FastAPI, Request, HTTPException, Query, Header, Depends
    from fastapi.responses import StreamingResponse, Response
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
except ImportError:
    raise RuntimeError("Requires: fastapi uvicorn pydantic numpy (faiss-cpu optional)")

# ── LOGGING ───────────────────────────────────────────────────────────────────
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
        span_id =request.headers.get("x-span-id",  str(uuid.uuid4())),
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
        lines = []
        for n, v in self.counters.items(): lines.append(f"# TYPE {n} counter\n{n} {v}")
        for n, v in self.gauges.items():   lines.append(f"# TYPE {n} gauge\n{n} {v}")
        return "\n".join(lines)

metrics = MetricsCollector()

# ── CONFIG ────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    ram_l1_max_tokens: int  = 131072
    ram_l2_dim: int         = 384
    ram_l2_capacity: int    = 1000000
    ram_l3_path: str        = str(Path(os.getenv("ATHOS_L3_PATH", os.path.join(os.path.expanduser("~"), ".athos", "archive"))))
    ram_persistence_interval: int = 300
    io_error_retries: int   = 3
    net_bind: str           = "0.0.0.0"
    net_port: int           = 8000
    net_cors: str           = "*"
    sec_u_rivers_threshold: float = 0.85
    sec_rate_limit_window: int    = 60
    sec_rate_limit_max: int       = 1000

CONFIG = Config()

# ── SECURITY ──────────────────────────────────────────────────────────────────
def _require_api_key() -> str:
    key = os.getenv("ATHOS_API_KEY")
    if not key:
        raise RuntimeError("ATHOS_API_KEY env var must be set")
    return key

ATHOS_API_KEY = _require_api_key()

class AlignmentGate:
    def __init__(self, threshold: float = CONFIG.sec_u_rivers_threshold):
        self.threshold = threshold
        self.audit_chain: List[Dict] = []
        self.last_hash = "0" * 64
        self.quarantined: set = set()

    def compute_u_rivers(self, service_score: float, ego_score: float) -> float:
        return service_score - ego_score

    async def verify_and_log(self, action: str, actor: str, u_rivers_score: float, trace: TraceContext) -> bool:
        if actor in self.quarantined: return False
        passed = u_rivers_score >= self.threshold
        payload = json.dumps({"action": action, "actor": actor, "score": u_rivers_score,
                              "passed": passed, "trace": trace.trace_id, "prev": self.last_hash}, sort_keys=True)
        curr_hash = hashlib.sha256(payload.encode()).hexdigest()
        self.audit_chain.append({"hash": curr_hash, "ts": time.time()})
        self.last_hash = curr_hash
        await metrics.increment("alignment_checks")
        if not passed: await metrics.increment("alignment_violations")
        return passed

    def quarantine(self, session_id: str, reason: str):
        self.quarantined.add(session_id)
        logger.warning(f"QUARANTINE:{session_id}:{reason}", extra={"trace_id": "system"})

alignment = AlignmentGate()

class RateLimiter:
    def __init__(self):
        self.buckets: Dict[str, deque] = defaultdict(deque)
        self.lock = asyncio.Lock()
    async def is_allowed(self, key: str) -> bool:
        async with self.lock:
            now = time.time()
            b = self.buckets[key]
            while b and b[0] < now - CONFIG.sec_rate_limit_window: b.popleft()
            if len(b) >= CONFIG.sec_rate_limit_max: return False
            b.append(now); return True

rate_limiter = RateLimiter()

def sanitize_input(text: str) -> str:
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text).strip()

# ── MEMORY ────────────────────────────────────────────────────────────────────
@dataclass
class MemoryChunk:
    id: str; text: str; tokens: int; embedding: np.ndarray
    attention: float = 1.0; created: float = 0.0; l1_cached: bool = False

class ContextMemory:
    def __init__(self):
        self.l1: Dict[str, MemoryChunk] = {}
        self.l1_tokens = 0
        self.l2_keys: List[str] = []          # FIX: track insertion order for index→key mapping
        self.l2_meta: Dict[str, MemoryChunk] = {}
        self.l3_path = Path(CONFIG.ram_l3_path)
        self.l3_path.mkdir(parents=True, exist_ok=True)
        self.lock = asyncio.Lock()
        if HAS_FAISS:
            self.l2_index = faiss.IndexFlatL2(CONFIG.ram_l2_dim)
            self._fb = None
        else:
            self._fb = FallbackFAISS(CONFIG.ram_l2_dim)

    def _emb(self, text: str) -> np.ndarray:
        digest = hashlib.sha256(text.encode()).digest()
        raw = [float(b) / 255.0 for b in digest]
        # pad or truncate to dim
        dim = CONFIG.ram_l2_dim
        raw = (raw * (dim // len(raw) + 1))[:dim]
        return np.array(raw, dtype=np.float32)

    def _index_add(self, emb: np.ndarray, cid: str):
        vec = np.array([emb], dtype=np.float32)
        if HAS_FAISS:
            self.l2_index.add(vec)
        else:
            self._fb.add(vec, cid)
        self.l2_keys.append(cid)

    def _index_search(self, emb: np.ndarray, k: int):
        vec = np.array([emb], dtype=np.float32)
        n = len(self.l2_keys)
        if n == 0: return []
        k = min(k, n)
        if HAS_FAISS:
            _, indices = self.l2_index.search(vec, k)
        else:
            _, indices = self._fb.search(vec, k)
        result = []
        for idx in indices[0]:
            if 0 <= idx < len(self.l2_keys):
                result.append(self.l2_keys[idx])
        return result

    async def allocate(self, text: str, priority: str = "STANDARD") -> str:
        async with self.lock:
            cid = hashlib.sha256(text.encode()).hexdigest()[:16]
            tokens = len(text.split())
            emb = self._emb(text)
            chunk = MemoryChunk(id=cid, text=text, tokens=tokens, embedding=emb, created=time.time())
            if self.l1_tokens + tokens > CONFIG.ram_l1_max_tokens:
                await self._evict(tokens)
            self.l1[cid] = chunk; self.l1_tokens += tokens; chunk.l1_cached = True
            if len(self.l2_meta) < CONFIG.ram_l2_capacity:
                if cid not in self.l2_meta:
                    self._index_add(emb, cid)
                    self.l2_meta[cid] = chunk
            else:
                await self._page_to_l3(chunk)
            return cid

    async def retrieve(self, query: str, top_k: int = 15) -> List[MemoryChunk]:
        async with self.lock:
            if not self.l2_meta: return list(self.l1.values())
            q_emb = self._emb(query)
            cids = self._index_search(q_emb, top_k)
            res = []
            for cid in cids:
                c = self.l2_meta.get(cid)
                if c is None: continue
                if not c.l1_cached: await self._page_in(c)
                res.append(c)
            return res

    async def _evict(self, needed: int):
        while self.l1_tokens + needed > CONFIG.ram_l1_max_tokens and self.l1:
            victim = min(self.l1.values(), key=lambda x: (x.created, x.attention))
            self.l1.pop(victim.id); self.l1_tokens -= victim.tokens; victim.l1_cached = False

    async def _page_in(self, chunk: MemoryChunk):
        if self.l1_tokens + chunk.tokens > CONFIG.ram_l1_max_tokens: await self._evict(chunk.tokens)
        self.l1[chunk.id] = chunk; self.l1_tokens += chunk.tokens; chunk.l1_cached = True

    async def _page_to_l3(self, chunk: MemoryChunk):
        p = self.l3_path / f"{chunk.id}.json"
        p.write_text(json.dumps({"id": chunk.id, "text": chunk.text, "ts": chunk.created}))

    async def persist_state(self):
        for c in self.l2_meta.values(): await self._page_to_l3(c)
        await metrics.set_gauge("memory_l1_tokens", self.l1_tokens)

memory = ContextMemory()

# ── TOOL HAL ──────────────────────────────────────────────────────────────────
_IS_WINDOWS = platform.system() == "Windows"
_ALLOWED_SHELL_CMDS = (
    {"echo", "dir", "type", "cd", "ver"} if _IS_WINDOWS
    else {"echo", "ls", "cat", "pwd", "date", "uname"}
)

def _run_shell(command: str, timeout: int = 60):
    parts = command.strip().split()
    if not parts or parts[0] not in _ALLOWED_SHELL_CMDS:
        raise ValueError(f"Shell command not whitelisted: {parts[0] if parts else '(empty)'}")
    result = subprocess.run(parts, capture_output=True, text=True, timeout=timeout,
                            shell=_IS_WINDOWS)  # shell=True required on Windows for builtins
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

def _run_python(code: str, timeout: int = 10):
    """FIX: run in subprocess with timeout instead of bare exec."""
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=timeout)
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

class DriverRegistry:
    def __init__(self):
        self.drivers: Dict[str, Callable] = {}
        self.sessions: Dict[str, Dict] = defaultdict(dict)
        self.cache: Dict[str, Any] = {}
        self.lock = asyncio.Lock()

    def register(self, name: str, handler: Callable):
        self.drivers[name] = handler

    async def execute(self, name: str, params: Dict, session_id: Optional[str] = None) -> Any:
        if name not in self.drivers: raise ValueError(f"DRIVER_NOT_FOUND:{name}")
        # FIX: only pass explicitly declared params to driver, not full context blob
        import inspect
        sig = inspect.signature(self.drivers[name])
        safe_params = {k: v for k, v in params.items() if k in sig.parameters}
        cache_key = hashlib.sha256(json.dumps({"name": name, "params": safe_params}, sort_keys=True).encode()).hexdigest()
        if cache_key in self.cache: return self.cache[cache_key]
        handler = self.drivers[name]
        for attempt in range(CONFIG.io_error_retries):
            try:
                result = handler(**safe_params)
                if asyncio.iscoroutine(result): result = await result
                if session_id: self.sessions[session_id][name] = result
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
hal.register("run_shell",  _run_shell)
hal.register("run_python", _run_python)
hal.register("browse_url", lambda url, timeout=30: {"status": "navigated", "url": url})

# ── SKILL CHAIN ───────────────────────────────────────────────────────────────
class ChainStep(BaseModel):
    id: str
    driver: str
    params: Dict[str, Any]
    condition: Optional[str] = None
    depends_on: List[str] = []          # FIX: Pydantic plain default (not dataclasses.field)

class SkillChain:
    def __init__(self):
        self.log: List[Dict] = []
        self.failures: Dict[str, int] = defaultdict(int)

    async def execute_dag(self, steps: List[ChainStep], context: Dict[str, Any]) -> Dict[str, Any]:
        topo = self._topological_sort(steps)
        results = {}
        for step in topo:
            if step.condition:
                try:
                    if not eval(step.condition, {"__builtins__": {}}, {"ctx": context, "len": len, "str": str}):
                        continue
                except Exception: continue
            if self.failures[step.id] >= 5: continue
            try:
                # FIX: pass only step.params merged with results (not full context)
                merged = {**step.params, **{k: results[k] for k in step.depends_on if k in results}}
                res = await hal.execute(step.driver, merged, session_id=step.id)
                results[step.id] = res
                self.failures[step.id] = 0
                self.log.append({"step": step.id, "status": "SUCCESS", "ts": time.time()})
            except Exception as e:
                self.failures[step.id] += 1
                await metrics.increment("chain_failures")
                self.log.append({"step": step.id, "status": "FAILED", "error": str(e), "ts": time.time()})
                if self.failures[step.id] >= 5:
                    alignment.quarantine(step.id, "CIRCUIT_BREAKER_OPEN")
        return results

    def _topological_sort(self, steps: List[ChainStep]) -> List[ChainStep]:
        graph: Dict[str, List[str]] = defaultdict(list)
        in_degree: Dict[str, int] = {s.id: 0 for s in steps}
        for s in steps:
            for dep in s.depends_on:
                graph[dep].append(s.id); in_degree[s.id] += 1
        queue = deque([s.id for s in steps if in_degree[s.id] == 0])
        ordered = []
        step_map = {s.id: s for s in steps}
        while queue:
            node = queue.popleft(); ordered.append(step_map[node])
            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0: queue.append(neighbor)
        return ordered

chain_engine = SkillChain()

# ── API ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="ATHOS_PC_KERNEL_V3.0", version="3.0.0", openapi_url="/v1/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=[CONFIG.net_cors], allow_methods=["*"], allow_headers=["*"])

async def verify_auth(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    if x_api_key != ATHOS_API_KEY: raise HTTPException(403, "INVALID_KEY")
    if not await rate_limiter.is_allowed(x_api_key): raise HTTPException(429, "RATE_LIMITED")
    return x_api_key

@app.get("/health")
async def health():
    return {"status": "healthy", "uptime": time.time(), "alignment": "LOCKED"}

@app.get("/metrics")
async def metrics_endpoint():
    return Response(content=metrics.export_prometheus(), media_type="text/plain")  # FIX: Response imported

@app.post("/v1/chat")
async def chat(request: Request, payload: Dict[str, Any],
               auth: str = Depends(verify_auth), trace: TraceContext = Depends(get_trace_context)):
    goal = sanitize_input(str(payload.get("goal", "")))
    if not goal: raise HTTPException(400, "EMPTY_GOAL")
    cid = await memory.allocate(goal, priority="CRITICAL")
    # FIX: compute score from real request properties, not hardcoded values
    # Here we use a simple heuristic; replace with real scoring logic
    goal_len = len(goal)
    service_score = min(1.0, goal_len / 500)
    ego_score = 0.0
    score = alignment.compute_u_rivers(service_score, ego_score)
    if not await alignment.verify_and_log("chat_execution", auth, score, trace):
        raise HTTPException(403, "ALIGNMENT_GATE_FAILED")
    steps = [ChainStep(id="analyze", driver="run_python",
                       params={"code": f"print('Analyzing goal of length {goal_len}')"})]
    results = await chain_engine.execute_dag(steps, {"goal": goal})
    await metrics.increment("chat_requests")
    return {"job_id": cid, "results": results, "trace_id": trace.trace_id, "alignment_score": score}

@app.post("/v1/tools/exec")
async def tool_exec(payload: Dict[str, Any], auth: str = Depends(verify_auth),
                    trace: TraceContext = Depends(get_trace_context)):
    name = payload.get("name"); params = payload.get("params", {})
    if not name: raise HTTPException(400, "MISSING_TOOL_NAME")
    score = alignment.compute_u_rivers(0.9, 0.05)
    if not await alignment.verify_and_log(f"tool_{name}", auth, score, trace):
        raise HTTPException(403, "ALIGNMENT_GATE_FAILED")
    result = await hal.execute(name, params, session_id=trace.trace_id)
    return {"result": result, "trace_id": trace.trace_id}

@app.post("/v1/tools/parallel")
async def tool_parallel(payload: List[Dict], auth: str = Depends(verify_auth)):
    results = await hal.parallel(payload)
    await metrics.increment("parallel_tool_batches")
    return {"results": results}

@app.get("/v1/context/search")
async def search_context(q: str = Query(...), k: int = Query(5), auth: str = Depends(verify_auth)):
    chunks = await memory.retrieve(q, top_k=k)
    return {"chunks": [{"id": c.id, "preview": c.text[:100]} for c in chunks]}

@app.get("/v1/stream/demo")
async def stream_demo():
    async def event_stream():
        for i in range(5):
            yield json.dumps({"chunk": i, "ts": time.time()}) + "\n"
            await asyncio.sleep(0.2)
    return StreamingResponse(event_stream(), media_type="text/event-stream")

# ── BOOT ──────────────────────────────────────────────────────────────────────
async def boot_sequence():
    logger.info("BOOT_SEQUENCE_START")
    await memory.allocate("SYSTEM_INIT", priority="CRITICAL")
    hal.register("health_check", lambda: {"status": "OK"})
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
    finally:
        bg.cancel()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ATHOS PC Kernel V3.0")
    parser.add_argument("--port", type=int, default=CONFIG.net_port)
    parser.add_argument("--host", type=str, default=CONFIG.net_bind)
    args = parser.parse_args()
    CONFIG.net_port = args.port; CONFIG.net_bind = args.host
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main())
