"""DataBot 本地演示：日志规则扫描与历史记录。"""
import asyncio
import json
import re
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "predict"
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "databot.sqlite3"
MAX_UPLOAD = 300 * 1024 * 1024
LOG_START = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}")
LEVEL = re.compile(r"\]\s*(INFO|WARNING|WARN|ERROR|CRITICAL|FATAL)\b", re.I)
TRACEBACK = re.compile(r"Traceback \(most recent call last\):")
EXCEPTION = re.compile(r"\b([A-Za-z_][\w.]*(?:Error|Exception))\b")

def connect():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


@asynccontextmanager
async def lifespan(_app):
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY, filename TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, elapsed REAL, result TEXT, error TEXT)""")
        db.execute("UPDATE analyses SET status='failed', error='服务重启，任务未完成' WHERE status IN ('pending', 'running')")
    yield


app = FastAPI(title="DataBot 本地日志分析 Demo", lifespan=lifespan)


def update(job_id, **fields):
    with connect() as db:
        db.execute(f"UPDATE analyses SET {', '.join(f'{key} = ?' for key in fields)} WHERE id = ?", (*fields.values(), job_id))


def scan_log(path):
    """Stream records; only counts and short, locally displayed examples are retained."""
    counts = {"records": 0, "error": 0, "warning": 0, "traceback": 0}
    examples = []
    record = []
    record_size = 0
    truncated = False

    def flush():
        nonlocal record, record_size, truncated
        if not record:
            return
        head = record[0]
        match = LEVEL.search(head[:400])
        level = match.group(1).upper() if match else ""
        text = "".join(record)
        trace = bool(TRACEBACK.search(text))
        if level in ("ERROR", "CRITICAL", "FATAL"):
            counts["error"] += 1
        elif level in ("WARNING", "WARN"):
            counts["warning"] += 1
        if trace:
            counts["traceback"] += 1
        if (level in ("ERROR", "CRITICAL", "FATAL", "WARNING", "WARN") or trace) and len(examples) < 10:
            kind = "错误" if level in ("ERROR", "CRITICAL", "FATAL") or trace else "警告"
            exc = EXCEPTION.search(text)
            examples.append({"line": record_line, "type": kind, "exception": exc.group(1) if exc else None,
                             "excerpt": text[:1200], "truncated": len(text) > 1200 or truncated})
        counts["records"] += 1
        record, record_size, truncated = [], 0, False

    record_line = 1
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line_no, line in enumerate(source, 1):
            if LOG_START.match(line) and record:
                flush()
                record_line = line_no
            if record_size < 16384:
                remaining = 16384 - record_size
                record.append(line[:remaining])
                record_size += min(len(line), remaining)
                if len(line) > remaining:
                    truncated = True
            else:
                truncated = True
        flush()
    return {"counts": counts, "examples": examples, "example_limit": 10,
            "note": "规则扫描结果，尚未接入模型分析；错误、警告和堆栈数量可能重叠。"}


def process(job_id, path, delete_after):
    start = time.monotonic()
    try:
        update(job_id, status="running")
        result = scan_log(path)
        update(job_id, status="completed", elapsed=round(time.monotonic() - start, 2), result=json.dumps(result, ensure_ascii=False))
    except Exception as exc:
        update(job_id, status="failed", elapsed=round(time.monotonic() - start, 2), error=f"日志读取或扫描失败：{type(exc).__name__}")
    finally:
        if delete_after:
            path.unlink(missing_ok=True)


def new_job(filename):
    job_id = uuid4().hex
    with connect() as db:
        db.execute("INSERT INTO analyses(id,filename,status,created_at) VALUES(?,?,?,?)",
                   (job_id, filename, "pending", datetime.now(timezone.utc).isoformat()))
    return job_id


class AnalyzeRequest(BaseModel):
    filename: str


@app.get("/api/logs")
def list_logs():
    return [{"name": p.name, "size": p.stat().st_size} for p in sorted(LOG_DIR.glob("*.log"), reverse=True)
            if p.is_file() and not p.is_symlink()]


@app.post("/api/analyze", status_code=202)
async def analyze(request: AnalyzeRequest):
    name = request.filename
    path = LOG_DIR / name
    if Path(name).name != name or not name.endswith(".log") or path.is_symlink() or not path.is_file() or path.resolve().parent != LOG_DIR.resolve():
        raise HTTPException(400, "日志文件不存在或不允许访问")
    job_id = new_job(name)
    asyncio.create_task(asyncio.to_thread(process, job_id, path, False))
    return {"id": job_id}


@app.post("/api/upload", status_code=202)
async def upload(file: UploadFile = File(...)):
    name = Path(file.filename or "").name
    if not name.lower().endswith((".log", ".txt")):
        raise HTTPException(400, "请选择 .log 或 .txt 文件")
    size = 0
    temp_path = None
    try:
        with NamedTemporaryFile(dir=DATA_DIR, prefix="upload_", delete=False) as temp:
            temp_path = Path(temp.name)
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, "文件超过 300 MiB")
                temp.write(chunk)
        job_id = new_job(name)
        asyncio.create_task(asyncio.to_thread(process, job_id, temp_path, True))
        return {"id": job_id}
    except BaseException:
        if temp_path:
            temp_path.unlink(missing_ok=True)
        raise
    finally:
        await file.close()


def serialize(row):
    result = dict(row)
    result["result"] = json.loads(result["result"]) if result["result"] else None
    return result


@app.get("/api/analyses")
def history():
    with connect() as db:
        return [serialize(row) for row in db.execute("SELECT * FROM analyses ORDER BY created_at DESC LIMIT 50")]


@app.get("/api/analyses/{job_id}")
def get_analysis(job_id: str):
    with connect() as db:
        row = db.execute("SELECT * FROM analyses WHERE id = ?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(404, "分析任务不存在")
    return serialize(row)
