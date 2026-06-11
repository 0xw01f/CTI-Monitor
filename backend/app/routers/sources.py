from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Source, Threat
from ..services.admin_auth import require_admin
from ..services.poller import poll_all_sources, poll_source

router = APIRouter(prefix="/api/sources", tags=["sources"])


def _to_dict(s: Source, db: Session) -> dict:
    return {
        "id": s.id,
        "connector": f"connector-{s.id}",
        "type": s.type,
        "active": s.active,
        "last_fetch": s.last_fetch.isoformat() if s.last_fetch else None,
        "fetch_interval": s.fetch_interval,
        "quality_score": s.quality_score,
        "error_count": s.error_count,
        "last_error": s.last_error,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "threat_count": db.query(Threat).filter(Threat.source_id == s.id).count(),
    }


@router.get("/")
def list_sources(db: Session = Depends(get_db)):
    return [_to_dict(s, db) for s in db.query(Source).all()]


@router.post("/")
def create_source(
    data: dict,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    allowed = {"name", "url", "type", "category", "fetch_interval", "quality_score"}
    source = Source(**{k: v for k, v in data.items() if k in allowed})
    db.add(source)
    db.commit()
    db.refresh(source)
    return _to_dict(source, db)


@router.patch("/{source_id}")
def update_source(
    source_id: int,
    data: dict,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    source = db.query(Source).filter(Source.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Not found")
    for k, v in data.items():
        if hasattr(source, k):
            setattr(source, k, v)
    db.commit()
    return _to_dict(source, db)


@router.delete("/{source_id}")
def delete_source(
    source_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    source = db.query(Source).filter(Source.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(source)
    db.commit()
    return {"ok": True}


@router.post("/poll-all")
async def trigger_poll_all(
    background_tasks: BackgroundTasks,
    _: dict = Depends(require_admin),
):
    background_tasks.add_task(poll_all_sources)
    return {"status": "polling all sources"}


@router.post("/{source_id}/poll")
async def trigger_poll(
    source_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    if not db.query(Source).filter(Source.id == source_id).first():
        raise HTTPException(status_code=404, detail="Not found")
    background_tasks.add_task(poll_source, source_id)
    return {"status": "polling started"}
