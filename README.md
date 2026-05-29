# 🛡️ HB-Eval: Secure Cognitive Runtime Gateway

**Version:** 1.0 (Production Kernel)
**Status:** Private / Confidential IP

## 📌 Overview
**HB-Eval** is the world's first Secure Cognitive Runtime for evaluating and ensuring the reliability of Autonomous Agentic Systems. This repository contains the **Hardened Gateway**, which serves as the central backend pipeline for the HB-Eval Reliability OS.

Unlike traditional post-execution evaluation tools, this gateway acts as an active immune system and cognitive memory center for AI agents, integrating mathematical evaluation, tactical control, and semantic memory.

## 🏗️ Core Architecture

1. **Security Pipeline (The Shield):**
   - **End-to-End Encryption:** Uses `AES-256-GCM` to ensure agent trajectories are encrypted before leaving the client environment.
   - **Replay Attack Protection:** Implements `HMAC-SHA256` signatures and `Redis`-backed single-use nonces.
   - **Safe Halt Protocol:** Enforces mandatory agent termination (Signal 99) if connectivity to the cognitive core is lost.

2. **Cognitive Engines (The Brain):**
   - Calculates **PEI** (Planning Efficiency Index) dynamically using $L_{min}$ and Constraint Violations.
   - Calculates **IRS** (Intentional Recovery Score) based on explicit memory queries and recovery efficiency.
   
3. **Evaluation-Driven Memory (EDM):**
   - Selective retention: Only trajectories achieving `PEI ≥ 0.80` are committed to memory.
   - Powered by `Supabase` and `pgvector` for semantic retrieval using `all-MiniLM-L6-v2` embeddings.

## 🚀 API Endpoints
- `GET /health` : System diagnostics (Supabase, Redis, Embeddings).
- `POST /api/v1/evaluate` : Secure endpoint for trajectory evaluation and EDM storage.
- `POST /api/v1/memory/retrieve` : Semantic search for retrieving successful past episodes.

## ⚠️ Confidentiality Notice
This repository contains proprietary algorithms and core IP for the HB-Eval architecture. Unauthorized access, distribution, or reverse engineering is strictly prohibited.
