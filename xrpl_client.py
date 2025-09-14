# xrpl_client.py
import time
from xrpl.clients import JsonRpcClient
from xrpl.wallet import Wallet, generate_faucet_wallet
from xrpl.models.transactions import TrustSet, EscrowCreate, EscrowFinish
from xrpl.models.amounts import IssuedCurrencyAmount
from xrpl.transaction import submit_and_wait
from xrpl.utils import xrp_to_drops

CLIENT = JsonRpcClient("https://s.altnet.rippletest.net:51234")

def create_wallet():
    return generate_faucet_wallet(CLIENT, debug=False)

def setup_trustline(wallet: Wallet, issuer_address: str, currency="USD", limit="1000000"):
    tx = TrustSet(
        account=wallet.classic_address,
        limit_amount=IssuedCurrencyAmount(currency=currency, issuer=issuer_address, value=limit)
    )
    return submit_and_wait(tx, CLIENT, wallet)

def create_escrow(sender_wallet: Wallet, dest_address: str, amount: str, currency="XRP", finish_after_seconds=5):
    if currency != "XRP":
        raise ValueError("XRPL EscrowCreate only supports XRP")
    finish_after = int(time.time()) + int(finish_after_seconds)
    drops = xrp_to_drops(float(amount))
    tx = EscrowCreate(
        account=sender_wallet.classic_address,
        destination=dest_address,
        amount=str(drops),
        finish_after=finish_after
    )
    return submit_and_wait(tx, CLIENT, sender_wallet)

def finish_escrow(wallet: Wallet, owner: str, escrow_sequence: int):
    tx = EscrowFinish(
        account=wallet.classic_address,
        owner=owner,
        offer_sequence=escrow_sequence
    )
    return submit_and_wait(tx, CLIENT, wallet)