from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import PlainTextResponse
from pathlib import Path

app = FastAPI()

BASE = Path("/app/storage")
RBASE = BASE / "r"
ACLBASE = BASE / "acl"

def safe_path(root: Path, subpath: str) -> Path:
    # prevent ../ traversal
    p = (root / subpath).resolve()
    if not str(p).startswith(str(root.resolve())):
        raise HTTPException(status_code=400, detail="Invalid path")
    return p

def acl_url_for(subpath: str) -> str:
    # WebAuthGuard expects ACL at /acl/<path> and Link rel="acl"
    return f"</acl/{subpath}>; rel=\"acl\""

@app.get("/r/{subpath:path}")
def get_resource(subpath: str):
    f = safe_path(RBASE, subpath)
    if not f.exists():
        raise HTTPException(status_code=404, detail="Not found")
    data = f.read_text(encoding="utf-8")
    return PlainTextResponse(data, headers={"Link": acl_url_for(subpath)})

@app.put("/r/{subpath:path}")
async def put_resource(subpath: str, request: Request):
    f = safe_path(RBASE, subpath)
    f.parent.mkdir(parents=True, exist_ok=True)
    body = await request.body()
    f.write_bytes(body)
    return Response(status_code=204, headers={"Link": acl_url_for(subpath)})

@app.delete("/r/{subpath:path}")
def delete_resource(subpath: str):
    f = safe_path(RBASE, subpath)
    if f.exists():
        f.unlink()
    return Response(status_code=204, headers={"Link": acl_url_for(subpath)})

@app.get("/acl/{subpath:path}")
def get_acl(subpath: str):
    f = safe_path(ACLBASE, subpath + ".ttl")
    if not f.exists():
        raise HTTPException(status_code=404, detail="ACL not found")
    data = f.read_text(encoding="utf-8")
    return PlainTextResponse(data, media_type="text/turtle")