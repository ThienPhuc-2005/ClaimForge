export const LAB_SECRET = "claimforge-lab-hs256";
export const LAB_USERS = {
  alice: { email: "alice@lab.test", password: "demo", sub: "alice", invoices: [5512] },
  bob: { email: "bob@lab.test", password: "demo", sub: "bob", invoices: [8801] },
} as const;
