# AgentBeats 競賽情報

> 更新：2026-04-02 | Sprint 3: 2026-04-13 → 05-03

## 賽制

- 主辦：Berkeley RDI + Agentic AI MOOC (~40K 學員)
- 總獎金：>$1M（含雲端 credits）
- **雙賽道**：Main Agent Safety ($5K/$3K/$1K) + Lambda Security ($5K/$3K/$1K)
- 同一提交可參加兩個賽道，max $10K
- 評分（按重要性）：① Leaderboard ② Generality ③ Cost ④ Quality ⑤ Innovation
- Cost = API calls + compute time + token consumption（本地模型不算）
- Held-out tasks 驗證泛化（不能 hardcode）

## 運作方式

- 平台用 GitHub Actions 跑你的 Docker（免費算力）
- 不需要 24/7 server，不需要 VPS/Pod
- 你自己選何時提交（Quick Submit），Sprint 3 期間隨時可交
- 可以反覆迭代（改代碼→推→重交）

## 流程

1. 填團隊報名 https://forms.gle/1gHSomHUy87XWAH66
2. 推代碼 → GitHub Actions build Docker → ghcr.io
3. agentbeats.dev Register Agent → 填 Docker image
4. Quick Submit → 選 green benchmark → 平台跑評估 → 出分
5. 看結果 → 改 → 重推 → 重交

## 16 個 Green Benchmarks（出題者）

### Tier 1：核心安全（我們最強）
| Benchmark | 測什麼 | 重點 |
|-----------|--------|------|
| NAAMSE | 125K+ jailbreak, 25+ 突變策略 | **低 FP 率是關鍵** |
| ASB-Multiturn | 多輪 injection（藏在 tool output 裡） | 抵抗工具回傳的注入 |
| AgentBusters | 6 場域 5 類攻擊（YAML/injection/PII/poisoning） | 全面安全 |
| CBRN Sentinel | 化學/生物/放射/核安全 | TAP 對抗壓測 |
| AgentHarm | **50% 安全 + 50% 有用** | ⚠️ 過度拒絕會扣分 |

### Tier 2：推理+合規
| Benchmark | 測什麼 | 格式要求 |
|-----------|--------|---------|
| CIRISBench | 倫理推理 4 類（300 題） | **第一個詞必須是 ethical/unethical/reasonable/unreasonable** |
| Ethics-Bench | 微妙倫理風險（辯論式評分） | 主動識別風險，問澄清問題 |
| A2-Bench | 法規合規（HIPAA/GDPR/KYC） | 84 任務含社工操控 |
| Bayesian Truthfulness | 貝葉斯信念更新 | 展示認知謙遜 |
| PRISM-Bench | 文化智商（650 場景） | DAR<30%, SRS>70%, ICRR>65% |

### Tier 3：專項
| Benchmark | 測什麼 | 格式要求 |
|-----------|--------|---------|
| PersonaGym | 人設忠實+安全（12 人設） | **不能說「I'm an AI」** |
| DIPG-Safety | 醫療安全（小兒腦瘤） | **JSON: {analysis, proof, final}** |
| Sandbagging | 偵測刻意降智 | 二元分類 |
| Visible-Yet-Unreadable | 圖片文字辨識（多語言） | 只輸出文字，不解釋 |
| ConstraintBench | PDDL 規劃（50 題） | 符號驗證 |
| IntentGuard | 即時意圖偵測 | 早期階段 |
| IronShell | Agent 安全 | 細節不明 |

## 競爭狀況

- 安全賽道 **0 公開競爭者**
- Sprint 2 CAR-bench 只有 1 個活躍參賽者
- 唯一可見對手：cs194 課堂作業（80% appropriate, 75% unsafe refusal）
- 勝出模式：基礎設施可靠 > 花俏架構 / Cost 效率 / Held-out 泛化

## 報名連結

| 表單 | 連結 | 狀態 |
|------|------|------|
| 團隊報名 | https://forms.gle/1gHSomHUy87XWAH66 | ✅ 開放 |
| Sprint 3 提交 | 尚未公布（4/13 後） | ⬜ |
| Credit 申請 | https://forms.gle/Uya9wQ2DqPStheH39 | 可能已過期 |
| Discord | https://discord.gg/uqZUta3MYa | 加入 |

## 參考

- [官方頁面](https://rdi.berkeley.edu/agentx-agentbeats)
- [AgentBeats 平台](https://agentbeats.dev)
- [Agent Template](https://github.com/RDI-Foundation/agent-template)
- [Tutorial](https://github.com/RDI-Foundation/agentbeats-tutorial)
- [OpenAgentSafety（dry run 用）](https://github.com/cyberjj999/cs194-agentbeats-openagent-safety)
- [Lambda Security Arena 規則](https://docs.google.com/document/d/1LH5I6DcsEy6umcziouCrKN90aEUhpUoKUT0hlfdaqts/edit)
