# PCV3 recovery TEST ONLY fixture map

`manifest.json` is a frozen, independent recovery-oracle description over the
public normal-volume fixtures. It contains literal slot boundaries, recovery
ranges, final-record states, and outcomes. It is not produced by the recovery
implementation and contains no production credentials or operational data.

The referenced PCV files remain in `../normal/`; this directory deliberately
does not duplicate large binary fixtures.
