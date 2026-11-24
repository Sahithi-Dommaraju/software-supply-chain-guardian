"""Day 2 · Human Approval: "Do we apply it?"

No LLM and no automatic action. This agent turns every fix card into an approval request on
the dashboard. A person approves or rejects each one (with their name and an optional note)
through POST /api/scans/{id}/decisions; decisions are stored in the `decisions` table, apart
from the immutable scan record. Approved fixes are the input for a later build/test step,
which is not part of this pipeline.
"""


def run(state: dict) -> tuple[dict, dict]:
    cards = state.get("fixes", [])
    public = {
        "requests": [{"card_id": c["id"], "title": c["title"], "action": c["action"], "band": c["band"]} for c in cards],
        "policy": "Nothing is changed in the repository. Approval records intent only; build and test come later.",
        "_summary": f"{len(cards)} fixes awaiting a decision" if cards else "No fixes to approve",
    }
    return {}, public
