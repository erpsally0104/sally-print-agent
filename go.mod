// The agent deliberately has zero dependencies: everything it needs is in the
// standard library. It is a binary that users download and run on their own
// machines, so every third-party package would be supply-chain surface on a
// host we do not control.
module sallyerp.in/print-agent

go 1.23
