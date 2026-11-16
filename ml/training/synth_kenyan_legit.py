"""Generate SYNTHETIC legitimate Kenyan messages (M-Pesa confirmations, OTPs, bank alerts,
utility tokens, everyday chat) from templates.

Why: the public data has no Kenyan legit messages, so a model trained on it flags ordinary
M-Pesa confirmations and OTPs as scams. This is a stop-gap until real donated messages exist.

Rules (docs/DATA_PLAN.md): rows are marked `origin = synthetic`, are added to TRAINING ONLY,
and never enter validation or test. Names, numbers and codes are random; no real person's
data is used. Known risk: scammers imitate these exact formats (fake M-Pesa confirmations),
so teaching the model that the format is legit makes such fakes harder to catch by text alone.

Usage: python -m ml.training.synth_kenyan_legit [--rows 1200]
"""

from __future__ import annotations

import argparse
import random
import string

import pandas as pd

from ml.training.common import REPO_ROOT

OUT = "data/processed/sms_synth_ke_legit_v1.csv"

FIRST = ["JOHN", "MARY", "PETER", "GRACE", "DAVID", "FAITH", "JAMES", "MERCY", "BRIAN", "ESTHER",
         "KEVIN", "LUCY", "SAMUEL", "JANE", "DENNIS", "ANN", "COLLINS", "RUTH", "VICTOR", "JOYCE"]  # fmt: skip
LAST = ["KAMAU", "OTIENO", "WANJIRU", "MUTUA", "CHEBET", "ODHIAMBO", "NJERI", "KIPTOO", "ACHIENG",
        "MWANGI", "WAFULA", "NYAMBURA", "KOECH", "AKINYI", "MUTHONI", "BARASA", "OMONDI", "WAMBUI"]  # fmt: skip
BIZ = ["NAIVAS SUPERMARKET", "QUICKMART", "KPLC PREPAID", "ZUKU", "JAVA HOUSE", "TOTAL ENERGIES",
       "CARREFOUR", "NAIROBI WATER", "DSTV", "GOTV", "RUBIS", "BOLT", "UBER", "JUMIA", "GLOVO",
       "CHANDARANA", "SHELL", "NHIF", "HELB", "STAR TIMES"]  # fmt: skip
BANKS = ["KCB", "Equity", "Co-op Bank", "ABSA", "NCBA", "Stanbic", "DTB", "Family Bank", "I&M"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
          "October", "November", "December"]  # fmt: skip

TEMPLATES = [
    # M-Pesa (English)
    "{code} Confirmed. Ksh{amt} sent to {name} {phone} on {date} at {time}. New M-PESA balance is Ksh{bal}. Transaction cost, Ksh{fee}. Amount you can transact within the day is {lim}.",
    "{code} Confirmed. You have received Ksh{amt} from {name} {phone} on {date} at {time}. New M-PESA balance is Ksh{bal}.",
    "{code} Confirmed. Ksh{amt} paid to {biz}. on {date} at {time}. New M-PESA balance is Ksh{bal}. Transaction cost, Ksh{fee}.",
    "{code} Confirmed. Ksh{amt} sent to {biz} for account {acc} on {date} at {time}. New M-PESA balance is Ksh{bal}. Transaction cost, Ksh{fee}.",
    "{code} Confirmed. on {date} at {time} Withdraw Ksh{amt} from {agent} - {biz} New M-PESA balance is Ksh{bal}. Transaction cost, Ksh{fee}.",
    "{code} confirmed. You bought Ksh{small} of airtime on {date} at {time}. New M-PESA balance is Ksh{bal}. Transaction cost, Ksh0.00.",
    "{code} Confirmed. On {date} at {time} Give Ksh{amt} cash to {biz} New M-PESA balance is Ksh{bal}.",
    "{code} Confirmed. Fuliza M-PESA amount is Ksh {small}. Interest charged Ksh {fee}. Total Fuliza M-PESA outstanding amount is Ksh {amt} due on {date}.",
    "{code} Confirmed. Ksh{amt} transferred to M-Shwari account on {date} at {time}. M-PESA balance is Ksh{bal}. New M-Shwari saving account balance is Ksh{lim}.",
    # M-Pesa (Swahili)
    "{code} Imethibitishwa. Ksh{amt} imetumwa kwa {name} {phone} tarehe {date} saa {time}. Baki yako ya M-PESA ni Ksh{bal}. Gharama ya muamala ni Ksh{fee}.",
    "{code} Imethibitishwa. Umepokea Ksh{amt} kutoka kwa {name} {phone} tarehe {date} saa {time}. Baki yako mpya ya M-PESA ni Ksh{bal}.",
    "{code} Imethibitishwa. Ksh{amt} imelipwa kwa {biz} tarehe {date} saa {time}. Baki yako ya M-PESA ni Ksh{bal}.",
    # One-time codes
    "Your verification code is {otp}. Do not share this code with anyone.",
    "{otp} is your {bank} OTP. It expires in 5 minutes. Never share it with anyone, including bank staff.",
    "Your OTP is {otp}. Do not share this code with anyone.",
    "Nambari yako ya kuthibitisha ni {otp}. Usimpe mtu yeyote nambari hii.",
    "<#> {otp} is your {biz} verification code.",
    "Use {otp} to log in to your {bank} app. If you did not request this, ignore this message.",
    # Bank alerts
    "Dear Customer, your account {masked} has been credited with KES {amt} on {date}. Available balance KES {bal}. Ref {code}.",
    "Dear Customer, KES {amt} has been debited from your account {masked} on {date}. Available balance KES {bal}. Ref {code}.",
    "Your {bank} card ending {four} was used for KES {amt} at {biz} on {date} {time}. Available balance KES {bal}.",
    "Dear customer, your {bank} account statement for {month} is ready. Visit your nearest branch or log in to the app to view it.",
    "Dear Member, your monthly contribution of KES {amt} has been received on {date}. Thank you for saving with us.",
    "Dear customer, your loan repayment of KES {amt} has been received. Outstanding balance KES {bal}. Thank you.",
    # Utilities, telco, services
    "Token: {token} Units: {units} Amt: {amt} Mtr No: {meter} Date: {date} {time}",
    "You have received {units}MB data bundle valid until {date} {time}. Dial *544# to check your balance.",
    "Your data bundle is below 2MB. Dial *544# to buy more data.",
    "Dear Customer, your Bonga Points balance is {four}. Dial *126# to redeem.",
    "Dear Taxpayer, your return for the period ending {date} has been received. Acknowledgement number KRA{token}.",
    "Your order #{four} from {biz} has been dispatched and will be delivered on {date}.",
    "Reminder: your appointment at {biz} is on {date} at {time}. Reply STOP to opt out.",
    "Dear Parent, school reopens on {date}. Fee balance for term is KES {amt}. Kindly pay through the school account as usual.",
    "Your {biz} trip receipt: KES {small}. Thank you for riding with us.",
    "Dear customer, scheduled power maintenance will affect your area on {date} from {time}. We apologise for the inconvenience.",
    # Everyday chat (English, Swahili, Sheng)
    "Niko njiani, nitafika in {mins} minutes.",
    "Nimetuma ile pesa ya rent, confirm ukipata.",
    "Sasa, uko? Tuma ile document kwa email nikicheki.",
    "Mum amesema ununue maziwa na mkate ukikuja.",
    "Niaje buda, form ni gani leo jioni?",
    "Hi, are we still meeting at {time} tomorrow?",
    "Asante sana, nimepata. Tutaongea kesho.",
    "Class imepostponiwa hadi {date}, lecturer amesema.",
    "Umefika home salama? Nipigie ukifika.",
    "Chama meeting ni Saturday saa nane kwa {first}. Usichelewe.",
    "Nimekutumia {small} ya fare kama tulivyoongea, confirm.",
    "Please call me when you are free, nothing urgent.",
    "Happy birthday {first}! Tuonane weekend.",
    "Niko kwa jam Thika Road, nitachelewa kidogo.",
    "Lunch leo? Tupatane kwa canteen saa saba.",
    "Usisahau kubeba charger yangu kesho tafadhali.",
]  # fmt: skip


def _money(rng: random.Random, low: int, high: int) -> str:
    return f"{rng.randint(low, high):,}.00"


def render(template: str, rng: random.Random) -> str:
    first = rng.choice(FIRST)
    values = {
        "code": "".join(rng.choices(string.ascii_uppercase + string.digits, k=10)),
        "amt": _money(rng, 50, 45000),
        "small": str(rng.choice([20, 50, 100, 150, 200, 250, 300, 500])),
        "bal": _money(rng, 0, 90000),
        "fee": rng.choice(["0.00", "7.00", "13.00", "23.00", "33.00", "57.00"]),
        "lim": _money(rng, 100000, 499000),
        "name": f"{first} {rng.choice(LAST)}",
        "first": first.title(),
        "phone": f"07{rng.randint(10000000, 99999999)}",
        "date": f"{rng.randint(1, 28)}/{rng.randint(1, 12)}/{rng.choice([24, 25, 26])}",
        "time": f"{rng.randint(1, 12)}:{rng.randint(0, 59):02d} {rng.choice(['AM', 'PM'])}",
        "biz": rng.choice(BIZ),
        "bank": rng.choice(BANKS),
        "acc": str(rng.randint(100000, 99999999)),
        "agent": str(rng.randint(100000, 999999)),
        "otp": str(rng.randint(1000, 999999)),
        "masked": f"XXXXXX{rng.randint(1000, 9999)}",
        "four": str(rng.randint(1000, 9999)),
        "month": rng.choice(MONTHS),
        "token": "".join(rng.choices(string.digits, k=20)),
        "units": f"{rng.randint(5, 2000)}",
        "meter": str(rng.randint(10000000000, 99999999999)),
        "mins": str(rng.choice([5, 10, 15, 20, 30])),
    }
    return template.format(**values)


def generate(rows: int, seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)  # noqa: S311 - data generation, not security
    texts = list(dict.fromkeys(render(rng.choice(TEMPLATES), rng) for _ in range(rows * 2)))[:rows]
    return pd.DataFrame(
        {
            "id": [f"JSYN-{i:06d}" for i in range(len(texts))],
            "text": texts,
            "text_en": None,
            "original_label": "synthetic_legit",
            "label": "legit",
            "category": None,
            "language": "en+sw",
            "country": "KE",
            "origin": "synthetic",
            "source": "synth_ke_legit",
            "license": "own (synthetic)",
            "is_malicious": 0,
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--rows", type=int, default=1200)
    args = parser.parse_args()
    frame = generate(args.rows)
    frame.to_csv(REPO_ROOT / OUT, index=False)
    print(f"Wrote {len(frame)} synthetic legit rows to {OUT}")


if __name__ == "__main__":
    main()
