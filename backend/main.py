import os
import secrets
import uuid
from decimal import Decimal, InvalidOperation
from urllib.parse import urlencode

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from op_client import OpenPaymentsClient, OpenPaymentsError, normalize_wallet_address

load_dotenv()

SENDER_WALLET = os.environ["SENDER_WALLET_ADDRESS"]
KEY_ID = os.environ["KEY_ID"]
PRIVATE_KEY_PATH = os.environ["PRIVATE_KEY_PATH"]
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")

app = FastAPI(title="VoiceFirst Payment API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # hackathon only; restrict for anything real
    allow_methods=["*"],
    allow_headers=["*"],
)

client = OpenPaymentsClient(SENDER_WALLET, KEY_ID, PRIVATE_KEY_PATH)

# paymentId -> state (incoming payment, quote, pending grant, result)
store: dict[str, dict] = {}


def to_minor_units(amount: str, scale: int) -> str:
    try:
        d = Decimal(str(amount).replace(",", ""))
    except InvalidOperation:
        raise ValueError("That amount is not a valid number.")
    if d <= 0:
        raise ValueError("The amount must be greater than zero.")
    return str(int(d * (Decimal(10) ** scale)))


def from_minor_units(value: str, scale: int) -> str:
    d = Decimal(value) / (Decimal(10) ** scale)
    return format(d.normalize(), "f")


# ---------------- 1. resolve ----------------
@app.get("/api/resolve")
async def resolve(wa: str):
    try:
        doc = await client.get_wallet_address(wa)
        return {
            "ok": True,
            "walletAddress": doc["id"],
            "publicName": doc.get("publicName") or "",
            "assetCode": doc["assetCode"],
            "assetScale": doc["assetScale"],
        }
    except (OpenPaymentsError, KeyError):
        return {"ok": False, "error": "I could not find that wallet address."}


# ---------------- 2. prepare ----------------
class PrepareBody(BaseModel):
    receiverWalletAddress: str
    amount: str


@app.post("/api/payments/prepare")
async def prepare(body: PrepareBody):
    try:
        receiver = await client.get_wallet_address(body.receiverWalletAddress)
        sender = await client.get_wallet_address(SENDER_WALLET)
        value = to_minor_units(body.amount, receiver["assetScale"])

        # incoming payment (receiver's servers)
        in_grant = await client.request_grant(
            receiver["authServer"],
            [{"type": "incoming-payment", "actions": ["create", "read", "complete"]}],
        )
        incoming = await client.post_resource(
            receiver["resourceServer"].rstrip("/") + "/incoming-payments",
            in_grant["access_token"]["value"],
            {
                "walletAddress": receiver["id"],
                "incomingAmount": {
                    "value": value,
                    "assetCode": receiver["assetCode"],
                    "assetScale": receiver["assetScale"],
                },
            },
        )

        # quote (sender's servers)
        q_grant = await client.request_grant(
            sender["authServer"],
            [{"type": "quote", "actions": ["create", "read"]}],
        )
        quote = await client.post_resource(
            sender["resourceServer"].rstrip("/") + "/quotes",
            q_grant["access_token"]["value"],
            {"walletAddress": sender["id"], "receiver": incoming["id"], "method": "ilp"},
        )

        payment_id = uuid.uuid4().hex
        store[payment_id] = {
            "sender": sender,
            "incoming": incoming,
            "quote": quote,
            "grant": None,
            "result": None,
        }
        return {
            "ok": True,
            "paymentId": payment_id,
            "receiverName": receiver.get("publicName") or "",
            "sendAmount": from_minor_units(quote["debitAmount"]["value"], quote["debitAmount"]["assetScale"]),
            "receiveAmount": from_minor_units(quote["receiveAmount"]["value"], quote["receiveAmount"]["assetScale"]),
            "assetCode": quote["debitAmount"]["assetCode"],
        }
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (OpenPaymentsError, KeyError) as e:
        print("prepare failed:", e)
        return {"ok": False, "error": "I could not prepare the payment. Please try again."}


# ---------------- 3. authorize ----------------
class AuthorizeBody(BaseModel):
    paymentId: str


@app.post("/api/payments/authorize")
async def authorize(body: AuthorizeBody):
    state = store.get(body.paymentId)
    if not state:
        return {"ok": False, "error": "That payment was not found. Please start again."}
    try:
        sender, quote = state["sender"], state["quote"]
        nonce = secrets.token_urlsafe(16)
        callback = f"{BACKEND_URL}/api/payments/callback?" + urlencode({"paymentId": body.paymentId})
        grant = await client.request_grant(
            sender["authServer"],
            [{
                "type": "outgoing-payment",
                "actions": ["list", "list-all", "read", "read-all", "create"],
                "identifier": sender["id"],
                "limits": {"debitAmount": quote["debitAmount"]},
            }],
            interact={
                "start": ["redirect"],
                "finish": {"method": "redirect", "uri": callback, "nonce": nonce},
            },
        )
        state["grant"] = grant
        state["nonce"] = nonce
        return {"ok": True, "redirectUrl": grant["interact"]["redirect"]}
    except (OpenPaymentsError, KeyError) as e:
        print("authorize failed:", e)
        return {"ok": False, "error": "I could not open your wallet's approval page."}


# ---------------- 4. callback ----------------
def _result_redirect(ok: bool, message: str) -> RedirectResponse:
    q = urlencode({"status": "success" if ok else "failed", "message": message})
    return RedirectResponse(f"{FRONTEND_URL}/result?{q}", status_code=303)


@app.get("/api/payments/callback")
async def callback(paymentId: str = "", interact_ref: str = "", result: str = "", hash: str = ""):
    state = store.get(paymentId)
    if not state or not state.get("grant"):
        return _result_redirect(False, "That payment was not found.")
    if not interact_ref:
        # wallet sends result=grant_rejected (or similar) when the user declines
        state["result"] = "failed"
        return _result_redirect(False, "The payment was not approved. No money was sent.")
    try:
        # NOTE: the `hash` param could be verified against the nonce for extra security (planned).
        grant = state["grant"]
        cont = grant["continue"]
        final = await client.continue_grant(cont["uri"], cont["access_token"]["value"], interact_ref)
        token = final["access_token"]["value"]
        sender = state["sender"]
        await client.post_resource(
            sender["resourceServer"].rstrip("/") + "/outgoing-payments",
            token,
            {"walletAddress": sender["id"], "quoteId": state["quote"]["id"]},
        )
        state["result"] = "completed"
        q = state["quote"]
        sent = from_minor_units(q["debitAmount"]["value"], q["debitAmount"]["assetScale"])
        code = q["debitAmount"]["assetCode"]
        return _result_redirect(True, f"Payment successful. You sent {sent} {code}.")
    except (OpenPaymentsError, KeyError) as e:
        print("callback failed:", e)
        state["result"] = "failed"
        return _result_redirect(False, "The payment could not be completed. No money was sent.")


@app.get("/health")
async def health():
    return {"ok": True}