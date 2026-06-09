# Kestrel 🦅

> Zero-instrumentation database query analyzer powered by eBPF

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)]()
[![Twitter](https://img.shields.io/twitter/follow/kestrel_dev)]()

**Currently in development. Follow the build →** [@kestrel_dev]()

---

## The Problem

Your app is slow. You suspect the database.

But seeing exactly which queries are the problem means adding SDKs,
changing your code, redeploying — or paying $79–300/month for
tools like pganalyze or Datadog APM.

Most small teams skip it entirely and just guess.

---

## What We're Building

Kestrel is a database query analyzer that works with **zero changes
to your code.**

Run one command alongside your Postgres database.
Kestrel uses eBPF to intercept queries at the Linux kernel level —
before they ever touch your app — and shows you:

- Which queries are the slowest
- Which queries run way too often (N+1 problems)
- Which service or process is responsible

Any language. Any framework. No instrumentation. No redeploy.

---

## Why eBPF

eBPF lets us attach to the Linux kernel and read network traffic
passively — without modifying your application or database in any way.

It's the same technology used by Datadog, Cloudflare, and Meta
for production observability. We're bringing it to teams who
can't afford those tools.

---

## Status

🔨 Actively building. Nothing to install yet.

We're building this fully in public — every decision, every mistake,
every shipped feature documented openly.

Follow along:
- 🐦 Twitter: [@kestrel_dev]()
- 📺 YouTube: [Kestrel Dev]()

---

## License

Apache 2.0
