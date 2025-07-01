import os
import sqlite3
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.websockets import WebSocketState
from passlib.context import CryptContext
import secrets


# --- SETUP AND DB UTILS ---

DB_FILE = os.getenv("QUIZREALM_DB_FILE", "quizrealm.db")


def get_db_conn():
    """Get new SQLite DB connection. Each call returns a new one. Used by endpoints for isolation."""
    return sqlite3.connect(
        DB_FILE,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
    )


def init_db():
    """Initialize tables if not exist."""
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            created_at DATETIME
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT,
            created_at DATETIME,
            expires_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS quiz_rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_code TEXT UNIQUE,
            created_by INTEGER,
            is_active BOOLEAN,
            created_at DATETIME,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS quiz_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER,
            question TEXT,
            choices TEXT,
            correct_index INTEGER,
            order_idx INTEGER,
            FOREIGN KEY (room_id) REFERENCES quiz_rooms (id)
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS room_participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER,
            user_id INTEGER,
            joined_at DATETIME,
            score INTEGER DEFAULT 0,
            FOREIGN KEY (room_id) REFERENCES quiz_rooms (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            room_id INTEGER,
            question_id INTEGER,
            selected_index INTEGER,
            is_correct BOOLEAN,
            answered_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (room_id) REFERENCES quiz_rooms (id),
            FOREIGN KEY (question_id) REFERENCES quiz_questions (id)
        )
        '''
    )
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS user_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            room_id INTEGER,
            score INTEGER,
            played_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (room_id) REFERENCES quiz_rooms (id)
        )
        '''
    )
    conn.commit()
    conn.close()


init_db()


# --- APP & CORS ---

app = FastAPI(
    title="QuizRealm Backend API",
    description=(
        "QuizRealm: Multiplayer quiz platform backend. "
        "Provides REST, WebSocket endpoints, authentication, "
        "quiz management, leaderboard, user dashboards, and DB health."
    ),
    version="1.0.0",
    openapi_tags=[
        {"name": "Auth", "description": "User authentication"},
        {"name": "Lobby", "description": "Quiz room/lobby management"},
        {"name": "Quiz", "description": "Quiz real-time WebSocket play"},
        {"name": "Dashboard", "description": "User stats & history"},
        {"name": "Internal", "description": "Health check, admin"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


def verify_password(plain, hash_):
    return pwd_context.verify(plain, hash_)


def hash_password(pw):
    return pwd_context.hash(pw)


def create_session(user_id: int, duration_min=60) -> str:
    """Create a session: insert into db, return session token."""
    token = secrets.token_hex(32)
    now = datetime.utcnow()
    expires = now + timedelta(minutes=duration_min)
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sessions (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, token, now, expires)
    )
    conn.commit()
    conn.close()
    return token


def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    """Return the user dict for a given bearer token, or None."""
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        '''
        SELECT u.id, u.username, u.created_at FROM users u
        JOIN sessions s ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > ?
        ORDER BY s.created_at DESC LIMIT 1
        ''',
        (token, datetime.utcnow())
    )
    row = cur.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "created_at": row[2]}
    return None


async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


class UserSignup(BaseModel):
    username: str = Field(..., example="user123")
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str


class RoomCreateRequest(BaseModel):
    room_code: Optional[str] = None
    questions: List[Dict] = Field(
        ...,
        description="List of questions (dict: question, choices, correct_index)"
    )


class RoomResponse(BaseModel):
    id: int
    room_code: str
    is_active: bool
    created_by: int
    created_at: datetime


class LobbyListItem(BaseModel):
    id: int
    room_code: str
    created_by: str
    is_active: bool
    participants: int


class QuizQuestionModel(BaseModel):
    id: int
    question: str
    choices: List[str]
    order_idx: int


class LeaderboardEntry(BaseModel):
    username: str
    score: int


class DashboardHistoryItem(BaseModel):
    room_code: str
    played_at: datetime
    score: int


@app.post("/auth/signup", summary="Sign up", tags=["Auth"])
def signup(req: UserSignup):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (req.username.lower(),))
    if cur.fetchone():
        conn.close()
        raise HTTPException(status_code=409, detail="Username already exists")
    hash_pw = hash_password(req.password)
    now = datetime.utcnow()
    cur.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (req.username.lower(), hash_pw, now)
    )
    user_id = cur.lastrowid
    conn.commit()
    conn.close()
    return {"message": "Signup successful", "id": user_id}


@app.post("/auth/token", summary="Login (get JWT/token)", tags=["Auth"])
def login(form: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, password_hash FROM users WHERE username=?",
        (form.username.lower(),)
    )
    row = cur.fetchone()
    if not row or not verify_password(form.password, row[2]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_id = row[0]
    token = create_session(user_id)
    conn.close()
    return {"access_token": token, "token_type": "bearer"}


@app.post("/auth/logout", summary="Logout (invalidate session)", tags=["Auth"])
def logout(token: str = Depends(oauth2_scheme)):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE token=?", (token,))
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return {"message": "Logged out" if affected else "No active session"}


@app.get(
    "/auth/me",
    response_model=UserResponse,
    summary="Get current user",
    tags=["Auth"]
)
def me(user=Depends(get_current_user)):
    return {"id": user["id"], "username": user["username"]}


def make_room_code() -> str:
    """Generates a short room code like 'QZAX1'."""
    return secrets.token_hex(3).upper()


@app.post(
    "/lobby/create",
    response_model=RoomResponse,
    summary="Create Quiz Room",
    tags=["Lobby"]
)
def create_room(req: RoomCreateRequest, user=Depends(get_current_user)):
    conn = get_db_conn()
    cur = conn.cursor()
    room_code = req.room_code or make_room_code()
    now = datetime.utcnow()
    cur.execute(
        "INSERT INTO quiz_rooms (room_code, created_by, is_active, created_at) VALUES (?, ?, ?, ?)",
        (room_code, user["id"], 1, now)
    )
    room_id = cur.lastrowid
    for idx, q in enumerate(req.questions):
        cur.execute(
            "INSERT INTO quiz_questions "
            "(room_id, question, choices, correct_index, order_idx) VALUES (?, ?, ?, ?, ?)",
            (room_id, q["question"], '|'.join(q["choices"]), q["correct_index"], idx)
        )
    cur.execute(
        "INSERT INTO room_participants (room_id, user_id, joined_at, score) VALUES (?, ?, ?, ?)",
        (room_id, user["id"], now, 0)
    )
    conn.commit()
    conn.close()
    return RoomResponse(
        id=room_id, room_code=room_code, is_active=True,
        created_by=user["id"], created_at=now
    )


@app.get(
    "/lobby/list",
    response_model=List[LobbyListItem],
    summary="List active quiz rooms",
    tags=["Lobby"]
)
def list_rooms():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        '''
        SELECT r.id, r.room_code, u.username, r.is_active, 
            (SELECT COUNT(*) FROM room_participants rp WHERE rp.room_id = r.id)
        FROM quiz_rooms r
        JOIN users u ON r.created_by = u.id
        WHERE r.is_active = 1
        ORDER BY r.created_at DESC
        '''
    )
    rooms = [
        LobbyListItem(
            id=row[0], room_code=row[1], created_by=row[2],
            is_active=bool(row[3]), participants=row[4]
        )
        for row in cur.fetchall()
    ]
    conn.close()
    return rooms


@app.post(
    "/lobby/join",
    summary="Join a quiz room by code",
    tags=["Lobby"]
)
def join_room(room_code: str = Query(...), user=Depends(get_current_user)):
    """Join a quiz room as participant."""
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, is_active FROM quiz_rooms WHERE room_code=?", (room_code,))
    room = cur.fetchone()
    if not room:
        conn.close()
        raise HTTPException(status_code=404, detail="Room not found")
    if not room[1]:
        conn.close()
        raise HTTPException(status_code=400, detail="Room is no longer active")
    room_id = room[0]
    cur.execute(
        "SELECT id FROM room_participants WHERE room_id=? AND user_id=?",
        (room_id, user["id"])
    )
    if cur.fetchone():
        conn.close()
        return {"message": "Already joined"}
    now = datetime.utcnow()
    cur.execute(
        "INSERT INTO room_participants (room_id, user_id, joined_at, score) VALUES (?, ?, ?, 0)",
        (room_id, user["id"], now)
    )
    conn.commit()
    conn.close()
    return {"message": "Joined room", "room_id": room_id}


class ConnectionManager:
    """Tracks live WebSocket room, sends questions, answers, and leaderboard updates."""

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, room_code: str, websocket: WebSocket):
        await websocket.accept()
        if room_code not in self.active_connections:
            self.active_connections[room_code] = []
        self.active_connections[room_code].append(websocket)

    def disconnect(self, room_code: str, websocket: WebSocket):
        if (
            room_code in self.active_connections
            and websocket in self.active_connections[room_code]
        ):
            self.active_connections[room_code].remove(websocket)
            if not self.active_connections[room_code]:
                del self.active_connections[room_code]

    async def broadcast(self, room_code: str, message: dict):
        websockets = self.active_connections.get(room_code, [])
        for ws in websockets:
            if ws.application_state == WebSocketState.CONNECTED:
                await ws.send_json(message)


manager = ConnectionManager()


class QuizMsgType:
    QUESTION = "question"
    ANSWER = "answer"
    LEADERBOARD = "leaderboard"
    STATE = "state"
    FINISH = "finish"
    ERROR = "error"


@app.websocket("/ws/quiz/{room_code}")
async def websocket_quiz(websocket: WebSocket, room_code: str, token: str = Query(...)):
    """
    Quiz WebSocket: clients send token via ?token=.
    Session: [question, answer, leaderboard] events.
    """
    user = get_user_by_token(token)
    if not user:
        await websocket.accept()
        await websocket.send_json(
            {"type": QuizMsgType.ERROR, "detail": "Invalid session"}
        )
        await websocket.close(code=1008)
        return
    await manager.connect(room_code, websocket)
    user_id = user["id"]
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, is_active FROM quiz_rooms WHERE room_code = ?",
            (room_code,)
        )
        row = cur.fetchone()
        if not row or not row[1]:
            await websocket.send_json(
                {"type": QuizMsgType.ERROR, "detail": "Room does not exist or inactive"}
            )
            return
        room_id = row[0]
        cur.execute(
            "SELECT id FROM room_participants WHERE room_id=? AND user_id=?",
            (room_id, user_id)
        )
        if not cur.fetchone():
            await websocket.send_json(
                {"type": QuizMsgType.ERROR, "detail": "Join the room lobby first"}
            )
            return
        global room_game_states
        if 'room_game_states' not in globals():
            globals()['room_game_states'] = {}
        room_game_states = globals()['room_game_states']
        if room_code not in room_game_states:
            cur.execute(
                "SELECT id, question, choices, order_idx "
                "FROM quiz_questions WHERE room_id = ? ORDER BY order_idx",
                (room_id,)
            )
            questions = [
                {
                    "id": q[0],
                    "question": q[1],
                    "choices": q[2].split('|'),
                    "order_idx": q[3]
                }
                for q in cur.fetchall()
            ]
            room_game_states[room_code] = {
                "current_question_idx": 0,
                "questions": questions,
                "answered_users": set(),
                "scores": {},
                "start_time": datetime.utcnow(),
                "question_start": None,
            }
        state = room_game_states[room_code]
        if user_id not in state["scores"]:
            state["scores"][user_id] = 0
        while True:
            if state["current_question_idx"] >= len(state["questions"]):
                for uid, score in state["scores"].items():
                    cur.execute(
                        "INSERT INTO user_history "
                        "(user_id, room_id, score, played_at) VALUES (?, ?, ?, ?)",
                        (uid, room_id, score, datetime.utcnow())
                    )
                cur.execute("UPDATE quiz_rooms SET is_active=0 WHERE id=?", (room_id,))
                conn.commit()
                await manager.broadcast(
                    room_code, {
                        "type": QuizMsgType.FINISH,
                        "leaderboard": await get_leaderboard(room_id)
                    }
                )
                del room_game_states[room_code]
                break
            q_obj = state["questions"][state["current_question_idx"]]
            question_id = q_obj["id"]
            if state.get("question_start") is None:
                state["answered_users"] = set()
                state["question_start"] = datetime.utcnow()
                await manager.broadcast(
                    room_code, {
                        "type": QuizMsgType.QUESTION,
                        "question": {
                            "question": q_obj["question"],
                            "choices": q_obj["choices"],
                            "order_idx": q_obj["order_idx"]
                        },
                        "countdown": 15,
                    }
                )
            try:
                await websocket.receive_json(timeout=1)
            except Exception:
                pass
            now = datetime.utcnow()
            elapsed = (now - state["question_start"]).total_seconds()
            cur.execute(
                "SELECT COUNT(*) FROM room_participants WHERE room_id=?",
                (room_id,)
            )
            total_participants = cur.fetchone()[0]
            if len(state["answered_users"]) >= total_participants or elapsed >= 15:
                leaderboard = await get_leaderboard(room_id)
                await manager.broadcast(
                    room_code,
                    {
                        "type": QuizMsgType.LEADERBOARD",
                        "leaderboard": leaderboard
                    }
                )
                state["current_question_idx"] += 1
                state["question_start"] = None
            else:
                if websocket.client_state == WebSocketState.CONNECTED:
                    try:
                        data = await websocket.receive_json(timeout=0.1)
                        if data.get("type") == QuizMsgType.ANSWER:
                            idx = data.get("selected_index")
                            if user_id not in state["answered_users"]:
                                cur.execute(
                                    "SELECT correct_index FROM quiz_questions "
                                    "WHERE id=?",
                                    (question_id,)
                                )
                                correct_index = cur.fetchone()[0]
                                is_correct = int(idx == correct_index)
                                cur.execute(
                                    "INSERT INTO answers "
                                    "(user_id, room_id, question_id, selected_index, "
                                    "is_correct, answered_at) VALUES (?, ?, ?, ?, ?, ?)",
                                    (
                                        user_id, room_id, question_id,
                                        idx, is_correct, datetime.utcnow()
                                    )
                                )
                                if is_correct:
                                    state["scores"][user_id] += 1
                                    cur.execute(
                                        "UPDATE room_participants SET score = score + 1 "
                                        "WHERE room_id=? AND user_id=?",
                                        (room_id, user_id)
                                    )
                                state["answered_users"].add(user_id)
                                conn.commit()
                                await manager.broadcast(
                                    room_code,
                                    {
                                        "type": QuizMsgType.ANSWER,
                                        "by": user["username"],
                                        "correct": bool(is_correct)
                                    }
                                )
                    except Exception:
                        pass

    except WebSocketDisconnect:
        manager.disconnect(room_code, websocket)
    finally:
        if conn:
            conn.close()


@app.get(
    "/quiz/leaderboard/{room_code}",
    response_model=List[LeaderboardEntry],
    summary="Get leaderboard for quiz room",
    tags=["Quiz"]
)
async def get_leaderboard_api(room_code: str):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM quiz_rooms WHERE room_code=?", (room_code,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Room not found")
    leaderboard = await get_leaderboard(row[0])
    return leaderboard


async def get_leaderboard(room_id: int) -> List[LeaderboardEntry]:
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        '''
        SELECT u.username, rp.score 
        FROM room_participants rp
        JOIN users u ON rp.user_id = u.id
        WHERE rp.room_id = ?
        ORDER BY rp.score DESC, u.username
        ''',
        (room_id,)
    )
    leaderboard = [
        LeaderboardEntry(username=row[0], score=row[1]) for row in cur.fetchall()
    ]
    conn.close()
    return leaderboard


@app.get(
    "/dashboard/history",
    response_model=List[DashboardHistoryItem],
    summary="Get current user's match history",
    tags=["Dashboard"]
)
def user_history(user=Depends(get_current_user)):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        '''
        SELECT qr.room_code, uh.played_at, uh.score
        FROM user_history uh
        JOIN quiz_rooms qr ON uh.room_id = qr.id
        WHERE uh.user_id = ?
        ORDER BY uh.played_at DESC
        ''',
        (user["id"],)
    )
    history = [
        DashboardHistoryItem(room_code=row[0], played_at=row[1], score=row[2])
        for row in cur.fetchall()
    ]
    conn.close()
    return history


@app.get(
    "/health/db",
    summary="Check DB health/connectivity",
    tags=["Internal"]
)
def db_health_check():
    """
    Returns DB status. 200 if connected, 503 if broken.
    """
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        conn.close()
        return {"status": "ok", "db": "sqlite"}
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "detail": str(exc)}
        )


@app.get("/", summary="Root: health check", tags=["Internal"])
def root():
    return {"status": "QuizRealm backend running"}

# NOTES:
# - This implementation is fully self-contained, only depends on FastAPI, pydantic, passlib, starlette, sqlite3.
# - The in-memory per-room quiz game state is NOT distributed (for demo/local/one-process runs; use Redis or similar for prod).
# - Quiz questions are created by the room creator in /lobby/create
# - WebSocket answers: clients send {type: "answer", selected_index: <int>} and receive broadcast updates.
# - Leaderboards available both in real-time (/ws/quiz/...) and by REST ("quiz/leaderboard/{room_code}").
# - Dashboard/history tracks match scores per user.
