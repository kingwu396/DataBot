"""DataBot 本地演示：日志规则扫描与历史记录。"""
import asyncio
import json
import os
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
from model_agents import call_model, list_models, run_agents, validate_base_url

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "predict"
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "databot.sqlite3"
SECRET_PATH = DATA_DIR / "model_api_key"
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
        db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("UPDATE analyses SET status='failed', error='服务重启，任务未完成' WHERE status IN ('pending', 'running', 'recognizing', 'analyzing')")
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


def process(job_id, path, delete_after, config):
    start = time.monotonic()
    result = {}
    try:
        update(job_id, status="running")
        result = scan_log(path)
        result['note'] = '规则扫描仅作辅助；两个 Agent 的分析状态见下方。'
        update(job_id, result=json.dumps(result, ensure_ascii=False))

        def report(stage, details):
            result['agent_stage'] = stage
            result['recognition_progress'] = details
            update(job_id, status=stage, elapsed=round(time.monotonic() - start, 2), result=json.dumps(result, ensure_ascii=False))

        agents = run_agents(path, config, report, start)
        result['agents'] = agents
        result['agent_stage'] = 'completed' if agents['recognition']['complete'] else 'partial'
        status = 'completed' if agents['recognition']['complete'] else 'partial'
        update(job_id, status=status, elapsed=round(time.monotonic() - start, 2), result=json.dumps(result, ensure_ascii=False))
    except Exception as exc:
        if isinstance(exc, RuntimeError):
            message = str(exc)
        else:
            message = f"处理失败：{type(exc).__name__}"
        result['agent_stage'] = 'failed'
        update(job_id, result=json.dumps(result, ensure_ascii=False))
        update(job_id, status="failed", elapsed=round(time.monotonic() - start, 2), error=message)
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


class ModelProfile(BaseModel):
    base_url: str
    model: str


class ModelSettings(BaseModel):
    provider: str
    profiles: dict[str, ModelProfile]
    redact: bool = True
    api_key: str | None = None
    clear_api_key: bool = False


class ModelsRequest(BaseModel):
    provider: str
    base_url: str
    api_key: str | None = None


def default_settings():
    return {'provider': 'openai', 'redact': True, 'profiles': {
        'ollama': {'base_url': 'http://127.0.0.1:11434', 'model': ''},
        'openai': {'base_url': 'https://api.openai.com/v1', 'model': ''},
    }}


def load_settings():
    with connect() as db:
        row = db.execute("SELECT value FROM settings WHERE key='model'").fetchone()
    defaults = default_settings()
    if not row:
        return defaults
    saved = json.loads(row['value'])
    # Preserve settings saved by the earlier single-profile version.
    if 'profiles' not in saved:
        provider = saved.get('provider', 'ollama')
        if provider in defaults['profiles']:
            defaults['provider'] = provider
            defaults['profiles'][provider] = {'base_url': saved.get('base_url', ''), 'model': saved.get('model', '')}
        defaults['redact'] = saved.get('redact', True)
        return defaults
    for provider in defaults['profiles']:
        if provider in saved['profiles']:
            defaults['profiles'][provider].update(saved['profiles'][provider])
    defaults['provider'] = saved.get('provider', defaults['provider'])
    defaults['redact'] = saved.get('redact', True)
    return defaults


def task_settings():
    saved = load_settings()
    provider = saved['provider']
    config = {'provider': provider, 'redact': saved['redact'], **saved['profiles'][provider]}
    if not config.get('model'):
        raise HTTPException(400, '请先保存模型配置')
    if config['provider'] == 'openai' and SECRET_PATH.exists():
        config['api_key'] = SECRET_PATH.read_text(encoding='utf-8')
    return config


@app.get('/api/settings')
def get_settings():
    return {**load_settings(), 'has_api_key': SECRET_PATH.exists()}


@app.put('/api/settings')
def save_settings(settings: ModelSettings):
    if settings.provider not in ('ollama', 'openai'):
        raise HTTPException(400, '模型类型无效')
    if set(settings.profiles) != {'ollama', 'openai'}:
        raise HTTPException(400, '请保留本地和远程两套模型配置')
    profiles = {}
    for provider, profile in settings.profiles.items():
        try:
            base_url = validate_base_url(profile.base_url.strip()) if profile.base_url.strip() else ''
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        profiles[provider] = {'base_url': base_url, 'model': profile.model.strip()}
    if not profiles[settings.provider]['base_url'] or not profiles[settings.provider]['model']:
        raise HTTPException(400, '请填写当前模型的服务地址和模型名称')
    config = {'provider': settings.provider, 'profiles': profiles, 'redact': settings.redact}
    if settings.clear_api_key:
        SECRET_PATH.unlink(missing_ok=True)
    if settings.api_key:
        fd = os.open(SECRET_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as secret_file:
            secret_file.write(settings.api_key)
        os.chmod(SECRET_PATH, 0o600)
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('model',?)", (json.dumps(config),))
    return {**config, 'has_api_key': SECRET_PATH.exists()}


@app.post('/api/settings/test')
async def test_model_connection():
    config = task_settings()
    try:
        await asyncio.to_thread(call_model, config, '请简短回应。', '连接测试：请回复连接成功。', 30)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from None
    return {'ok': True}


@app.post('/api/settings/models')
async def get_available_models(request: ModelsRequest):
    if request.provider not in ('ollama', 'openai'):
        raise HTTPException(400, '模型类型无效')
    try:
        base_url = validate_base_url(request.base_url.strip())
        api_key = request.api_key or ''
        if request.provider == 'openai' and not api_key and SECRET_PATH.exists():
            saved_url = load_settings()['profiles']['openai']['base_url']
            if not saved_url or base_url != validate_base_url(saved_url):
                raise ValueError('服务地址已更改，请重新输入该服务的 API 密钥')
            api_key = SECRET_PATH.read_text(encoding='utf-8')
        models = await asyncio.to_thread(list_models, request.provider, base_url, api_key)
        return {'models': models}
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from None


@app.get("/api/logs")
def list_logs():
    return [{"name": p.name, "size": p.stat().st_size} for p in sorted(LOG_DIR.glob("*.log"), reverse=True)
            if p.is_file() and not p.is_symlink()]


@app.post("/api/analyze", status_code=202)
async def analyze(request: AnalyzeRequest):
    config = task_settings()
    name = request.filename
    path = LOG_DIR / name
    if Path(name).name != name or not name.endswith(".log") or path.is_symlink() or not path.is_file() or path.resolve().parent != LOG_DIR.resolve():
        raise HTTPException(400, "日志文件不存在或不允许访问")
    job_id = new_job(name)
    asyncio.create_task(asyncio.to_thread(process, job_id, path, False, config))
    return {"id": job_id}


@app.post("/api/upload", status_code=202)
async def upload(file: UploadFile = File(...)):
    config = task_settings()
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
        asyncio.create_task(asyncio.to_thread(process, job_id, temp_path, True, config))
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
