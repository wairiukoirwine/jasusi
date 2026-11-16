# JASUSI — Labelling guide

Use this when labelling donated or transcribed messages. Label the **anonymised** text only.

## Step 1 — binary label
- `scam`: tries to trick the reader into sending money, sharing a PIN/OTP/password, clicking a harmful
  link, or paying a fee for something that does not exist.
- `legit`: a genuine message, including genuine marketing from a real company and genuine requests
  from people the receiver knows.
- When you cannot tell, label `unsure` and add a note. Do not guess: unsure rows are reviewed by a
  second person and are excluded from the test set until resolved.

## Step 2 — category (only for `scam`)
Pick the **most specific** category that fits. If two fit, pick the one higher in this list.

| Category | Use when | Examples (invented) |
|---|---|---|
| `mpesa_reversal_scam` | Claims money was sent by mistake and asks for it back, or a fake M-Pesa confirmation followed by a refund request | "Nimekutumia 3,500 kimakosa, tafadhali rudisha kwa `<PHONE>`" · "Confirmed. You have received Ksh 4,000… please reverse, wrong number" |
| `impersonation` | Pretends to be a relative, friend, boss or landlord | "Hey mum, hii ni namba yangu mpya, nitumie 2000" · "Dear tenant, rent is now paid to `<PHONE>`" |
| `job_scam` | Job or easy-income offer that needs a fee, or is too good to be true | "You qualified for airport jobs, pay 1,200 medical fee via paybill…" · "Earn 5,000 per day from home, WhatsApp `<PHONE>`" |
| `loan_scam` | Loan offer that needs an upfront fee or personal details | "Your loan of 35,000 is approved. Pay 350 processing fee to Till…" |
| `fake_bank_or_kra` | Pretends to be a bank, KRA, eCitizen, NTSA, HELB or another agency | "KRA: iTax account suspended, verify your PIN at …" · "Your Equity account is locked, confirm password…" |
| `prize_or_promo_scam` | Prize, lottery, promotion or gift that you must pay or register to claim | "Congratulations! You won 50,000 in Safaricom promotion. Send 500 to claim" |
| `phishing_link` | The main trick is a link, and none of the above fits | "Your parcel is held. Update address: bit.ly/…" |
| `other_scam` | Clearly a scam but none of the above (e.g. "Illuminati/Freemason" recruitment, threats, fake fundraisers) | "Join Freemason and get rich, call `<PHONE>`" |

`legit` rows get the category `legit`.

## Hard cases
- **Real M-Pesa confirmation vs fake**: real ones start with a 10-character code and come from sender
  `MPESA`. If the donor says it came from an ordinary number, label `scam` (`mpesa_reversal_scam`).
- **A friend genuinely asking for money**: `legit`. Record the donor's statement in the note. Without
  that context, label `unsure`.
- **Aggressive but real marketing** (betting, loans from licensed apps): `legit`, note "promo".
- **Debt collection threats**: `unsure` unless the donor confirms.

## Quality control
- At least 20% of rows are labelled independently by a second person; report Cohen's kappa for the
  binary label and for the category.
- Disagreements are discussed, the final label is recorded, and the guide is updated when a new
  pattern appears.
- Columns to keep per row: `text` (anonymised), `label`, `category`, `language` (`en`, `sw`, `sheng`,
  mixed e.g. `en+sw`), `sender_type` (`shortcode`, `number`, `unknown`), `date_received` (month and
  year only), `labeller`, `note`.
