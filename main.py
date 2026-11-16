from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import sqlite3
import hashlib
import math
import time
import os
import uuid

app = FastAPI(title="Blink App")

os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

DB_PATH = "blink.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            age INTEGER NOT NULL,
            gender TEXT NOT NULL,
            interested_in TEXT NOT NULL,
            bio TEXT,
            avatar_url TEXT,
            is_visible INTEGER DEFAULT 0,
            lat REAL DEFAULT 0,
            lng REAL DEFAULT 0,
            last_seen REAL DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS blinks (
            id TEXT PRIMARY KEY,
            from_user_id TEXT NOT NULL,
            to_user_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at REAL NOT NULL,
            UNIQUE(from_user_id, to_user_id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> int:
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return round(2 * R * math.atan2(math.sqrt(a), math.sqrt(1 - a)))


def are_matched(c, user1_id: str, user2_id: str) -> bool:
    c.execute("""
        SELECT 1 FROM blinks
        WHERE status = 'matched'
          AND ((from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?))
    """, (user1_id, user2_id, user2_id, user1_id))
    return c.fetchone() is not None


class LoginRequest(BaseModel):
    username: str
    password: str


class ScanRequest(BaseModel):
    user_id: str
    is_visible: bool
    lat: float
    lng: float


class BlinkAction(BaseModel):
    from_user: str
    to_user_id: str


class RespondBlinkRequest(BaseModel):
    user_id: str
    blink_id: str
    accept: bool


class SendMessageRequest(BaseModel):
    sender_id: str
    receiver_id: str
    text: str


@app.get("/", response_class=HTMLResponse)
async def serve_app():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/api/register")
async def register(
    username: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(...),
    age: int = Form(...),
    gender: str = Form(...),
    interested_in: str = Form(...),
    bio: str = Form(""),
    avatar: UploadFile = File(None)
):
    username_clean = username.strip().lower()
    phone_clean = phone.strip()

    if len(username_clean) < 2 or len(password) < 4:
        raise HTTPException(status_code=400, detail="שם משתמש או סיסמה קצרים מדי")
    if len(phone_clean) < 9:
        raise HTTPException(status_code=400, detail="נא להזין מספר טלפון תקין")

    avatar_url = "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=300&h=300&fit=crop"
    if avatar and avatar.filename:
        ext = os.path.splitext(avatar.filename)[1] or ".jpg"
        file_name = f"{uuid.uuid4()}{ext}"
        file_path = os.path.join("uploads", file_name)
        with open(file_path, "wb") as f:
            f.write(await avatar.read())
        avatar_url = f"/uploads/{file_name}"

    user_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO users (id, username, phone, password_hash, display_name, age, gender, interested_in, bio, avatar_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username_clean, phone_clean, hash_password(password), display_name.strip(), age, gender, interested_in, bio.strip(), avatar_url))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="שם המשתמש הזה כבר תפוס")
    conn.close()

    return {
        "user": {
            "id": user_id,
            "username": username_clean,
            "phone": phone_clean,
            "display_name": display_name.strip(),
            "age": age,
            "gender": gender,
            "interested_in": interested_in,
            "bio": bio.strip(),
            "avatar_url": avatar_url
        }
    }


@app.post("/api/login")
async def login(req: LoginRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (req.username.strip().lower(), hash_password(req.password)))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="שם משתמש או סיסמה שגויים")

    return {
        "user": {
            "id": row["id"],
            "username": row["username"],
            "phone": row["phone"],
            "display_name": row["display_name"],
            "age": row["age"],
            "gender": row["gender"],
            "interested_in": row["interested_in"],
            "bio": row["bio"],
            "avatar_url": row["avatar_url"]
        }
    }


@app.post("/api/scan")
async def update_and_scan(data: ScanRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE id = ?", (data.user_id,))
    me = c.fetchone()
    if not me:
        conn.close()
        raise HTTPException(status_code=404, detail="משתמש לא נמצא")

    c.execute("""
        UPDATE users SET is_visible = ?, lat = ?, lng = ?, last_seen = ? WHERE id = ?
    """, (1 if data.is_visible else 0, data.lat, data.lng, time.time(), data.user_id))
    conn.commit()

    if not data.is_visible:
        conn.close()
        return {"nearby": []}

    c.execute("SELECT COUNT(*) FROM users WHERE id LIKE 'demo_%'")
    if c.fetchone()[0] == 0 and data.lat != 0:
        demos = [
            (
                "demo_1", "omer_demo", "0500000001", "1234", "עומר", 29, "male", "female",
                "יושב על הבר, שותה ג'ין טוניק",
                "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=300&h=300&fit=crop",
                1, data.lat + 0.00015, data.lng + 0.0001, time.time()
            ),
            (
                "demo_2", "maya_demo", "0500000002", "1234", "מאיה", 27, "female", "male",
                "רוקדת ליד העמדה",
                "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=300&h=300&fit=crop",
                1, data.lat - 0.0002, data.lng + 0.00015, time.time()
            )
        ]
        c.executemany("""
            INSERT OR IGNORE INTO users (
                id, username, phone, password_hash, display_name, age, gender,
                interested_in, bio, avatar_url, is_visible, lat, lng, last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, demos)
        conn.commit()

    c.execute("SELECT * FROM users WHERE is_visible = 1 AND id != ?", (data.user_id,))
    others = c.fetchall()

    nearby = []
    RADIUS_METERS = 150

    for u in others:
        my_pref_ok = (me["interested_in"] == "all" or me["interested_in"] == u["gender"])
        their_pref_ok = (u["interested_in"] == "all" or u["interested_in"] == me["gender"])
        if not (my_pref_ok and their_pref_ok):
            continue

        dist = haversine_meters(data.lat, data.lng, u["lat"], u["lng"])
        if dist <= RADIUS_METERS:
            c.execute("""
                SELECT status, from_user_id FROM blinks
                WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)
            """, (data.user_id, u["id"], u["id"], data.user_id))
            b_row = c.fetchone()
            blink_status = "none"
            if b_row:
                if b_row["status"] == "matched":
                    blink_status = "matched"
                elif b_row["from_user_id"] == data.user_id and b_row["status"] == "pending":
                    blink_status = "sent"
                elif b_row["to_user_id"] == data.user_id and b_row["status"] == "pending":
                    blink_status = "incoming"

            nearby.append({
                "user_id": u["id"],
                "name": u["display_name"],
                "age": u["age"],
                "bio": u["bio"],
                "distance": dist,
                "avatar": u["avatar_url"],
                "blink_status": blink_status
            })

    conn.close()
    nearby.sort(key=lambda x: x["distance"])
    return {"nearby": nearby}


@app.get("/api/heatmap")
async def get_heatmap():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT lat, lng FROM users WHERE is_visible = 1 AND lat != 0 AND lng != 0")
    rows = c.fetchall()
    conn.close()

    clusters = {}
    for lat, lng in rows:
        grid_lat = round(lat, 3)
        grid_lng = round(lng, 3)
        key = (grid_lat, grid_lng)
        clusters[key] = clusters.get(key, 0) + 1

    return [
        {"lat": k[0], "lng": k[1], "count": v}
        for k, v in clusters.items()
    ]


@app.post("/api/blink")
async def send_blink(action: BlinkAction):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT id, gender FROM users WHERE id = ?", (action.from_user,))
    sender = c.fetchone()
    c.execute("SELECT id, display_name FROM users WHERE id = ?", (action.to_user_id,))
    target = c.fetchone()
    if not sender or not target:
        conn.close()
        raise HTTPException(status_code=404, detail="משתמש לא נמצא")

    c.execute("""
        SELECT id FROM blinks WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending'
    """, (action.to_user_id, action.from_user))
    reverse_blink = c.fetchone()

    if reverse_blink:
        c.execute("UPDATE blinks SET status = 'matched' WHERE id = ?", (reverse_blink["id"],))
        conn.commit()
        conn.close()
        return {"status": "matched"}

    c.execute("""
        SELECT status FROM blinks
        WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)
    """, (action.from_user, action.to_user_id, action.to_user_id, action.from_user))
    existing = c.fetchone()
    if existing:
        conn.close()
        return {"status": existing["status"]}

    if action.to_user_id.startswith("demo_"):
        blink_id = str(uuid.uuid4())
        c.execute("""
            INSERT INTO blinks (id, from_user_id, to_user_id, status, created_at)
            VALUES (?, ?, ?, 'matched', ?)
        """, (blink_id, action.from_user, action.to_user_id, time.time()))
        welcome_msg = "היי! איזה כיף שאישרנו Blink, איפה יושבים?"
        c.execute("""
            INSERT INTO messages (id, sender_id, receiver_id, text, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (str(uuid.uuid4()), action.to_user_id, action.from_user, welcome_msg, time.time()))
        conn.commit()
        conn.close()
        return {"status": "matched"}

    blink_id = str(uuid.uuid4())
    c.execute("""
        INSERT INTO blinks (id, from_user_id, to_user_id, status, created_at)
        VALUES (?, ?, ?, 'pending', ?)
    """, (blink_id, action.from_user, action.to_user_id, time.time()))
    conn.commit()
    conn.close()
    return {"status": "sent"}


@app.get("/api/notifications/{user_id}")
async def get_notifications(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        SELECT b.id AS blink_id, b.created_at, u.id AS from_user_id,
               u.display_name, u.age, u.gender, u.bio, u.avatar_url
        FROM blinks b
        JOIN users u ON b.from_user_id = u.id
        WHERE b.to_user_id = ? AND b.status = 'pending'
        ORDER BY b.created_at DESC
    """, (user_id,))
    incoming_rows = c.fetchall()

    incoming = []
    for r in incoming_rows:
        interest_text = "מישהו מעוניין בך!" if r["gender"] == "male" else "מישהי מעוניינת בך!"
        incoming.append({
            "blink_id": r["blink_id"],
            "from_user_id": r["from_user_id"],
            "name": r["display_name"],
            "age": r["age"],
            "gender": r["gender"],
            "bio": r["bio"],
            "avatar": r["avatar_url"],
            "headline": interest_text
        })

    c.execute("""
        SELECT b.id AS blink_id,
               CASE WHEN b.from_user_id = ? THEN b.to_user_id ELSE b.from_user_id END AS partner_id
        FROM blinks b
        WHERE b.status = 'matched' AND (b.from_user_id = ? OR b.to_user_id = ?)
        ORDER BY b.created_at DESC
    """, (user_id, user_id, user_id))
    match_rows = c.fetchall()

    matches = []
    for m in match_rows:
        c.execute("SELECT id, display_name, age, bio, avatar_url FROM users WHERE id = ?", (m["partner_id"],))
        partner = c.fetchone()
        if partner:
            c.execute("""
                SELECT text FROM messages
                WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                ORDER BY created_at DESC LIMIT 1
            """, (user_id, partner["id"], partner["id"], user_id))
            last_msg_row = c.fetchone()
            matches.append({
                "user_id": partner["id"],
                "name": partner["display_name"],
                "age": partner["age"],
                "bio": partner["bio"],
                "avatar": partner["avatar_url"],
                "last_message": last_msg_row["text"] if last_msg_row else "התאמה הדדית! שלחו הודעה ראשונה"
            })

    conn.close()
    return {"incoming": incoming, "matches": matches}


@app.post("/api/blink/respond")
async def respond_blink(req: RespondBlinkRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM blinks WHERE id = ? AND to_user_id = ?", (req.blink_id, req.user_id))
    blink = c.fetchone()
    if not blink:
        conn.close()
        raise HTTPException(status_code=404, detail="בקשת ה-Blink לא נמצאה")

    if req.accept:
        c.execute("UPDATE blinks SET status = 'matched' WHERE id = ?", (req.blink_id,))
        conn.commit()
        conn.close()
        return {"status": "matched", "partner_id": blink["from_user_id"]}
    else:
        c.execute("UPDATE blinks SET status = 'declined' WHERE id = ?", (req.blink_id,))
        conn.commit()
        conn.close()
        return {"status": "declined"}


@app.get("/api/messages/{user_id}/{partner_id}")
async def get_messages(user_id: str, partner_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    if not are_matched(c, user_id, partner_id):
        conn.close()
        raise HTTPException(status_code=403, detail="הצ'אט חסום - נדרש Blink ואישור הדדי")

    c.execute("""
        SELECT id, sender_id, receiver_id, text, created_at
        FROM messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY created_at ASC
    """, (user_id, partner_id, partner_id, user_id))
    rows = c.fetchall()
    conn.close()

    return {
        "messages": [
            {
                "id": r["id"],
                "sender_id": r["sender_id"],
                "text": r["text"],
                "created_at": r["created_at"]
            }
            for r in rows
        ]
    }


@app.post("/api/messages")
async def send_message(req: SendMessageRequest):
    text_clean = req.text.strip()
    if not text_clean:
        raise HTTPException(status_code=400, detail="לא ניתן לשלוח הודעה ריקה")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if not are_matched(c, req.sender_id, req.receiver_id):
        conn.close()
        raise HTTPException(status_code=403, detail="לא ניתן לשלוח הודעה ללא Blink מאושר משני הצדדים")

    msg_id = str(uuid.uuid4())
    now = time.time()
    c.execute("""
        INSERT INTO messages (id, sender_id, receiver_id, text, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (msg_id, req.sender_id, req.receiver_id, text_clean, now))
    conn.commit()
    conn.close()

    return {"status": "sent", "id": msg_id, "created_at": now}