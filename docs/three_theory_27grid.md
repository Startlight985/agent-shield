# 三理論 27 格映射 — AI Agent 防禦領域

## 維度定義

- **維度一（被控對象）**：河床(WHERE) / 張力(WHEN) / 動態平衡(HOW MUCH)
- **維度二（控制透鏡）**：河床透鏡(穩定嗎?) / 張力透鏡(什麼條件啟動?) / 動態平衡透鏡(增還是減?)
- **維度三（尺度）**：小(per-message) / 中(per-session) / 大(per-domain)

---

## 小尺度（per-message，即時決策）

| # | 被控 | 透鏡 | 問題 | 映射 | 實作位置 |
|---|------|------|------|------|---------|
| 1 | 河床 | 河床 | 這條訊息的攻擊方向穩定嗎？ | B-score 四維相似度分佈的 entropy | `L1.entropy` |
| 2 | 河床 | 張力 | 什麼條件觸發資源重分配？ | B > suspect_threshold → 升級到 L3 | `L1.is_suspect` |
| 3 | 河床 | 動平 | 該給這條訊息多少防禦資源？ | MicroPosture 乘數（0.7/1.0/1.3） | `MicroPosture.posture_mult` |
| 4 | 張力 | 河床 | entropy 閾值計算穩定嗎？ | sigmoid 映射保證平滑，不跳變 | `_tension_threshold` sigmoid |
| 5 | 張力 | 張力 | 什麼條件觸發閾值收緊？ | 四維 entropy 高（模糊）→ 收緊 | `h_norm > 0.5 → tighten` |
| 6 | 張力 | 動平 | 閾值該收還是放？ | entropy 高→收，entropy 低→放 | `adjustment ∈ (0,1)` |
| 7 | 動平 | 河床 | 路由決策穩定嗎？ | 路由基於 preprocessor flags，確定性 | `DynBal.route()` |
| 8 | 動平 | 張力 | 什麼條件觸發路由切換？ | encoding/multilingual/multi-turn/prompt-boundary | `DefensePath` enum |
| 9 | 動平 | 動平 | 路由該走快路還是慢路？ | prompt_boundary→FAST_REJECT，else→STANDARD | `route()` 邏輯 |

## 中尺度（per-session，累積調參）

| # | 被控 | 透鏡 | 問題 | 映射 | 實作位置 |
|---|------|------|------|------|---------|
| 10 | 河床 | 河床 | session 攻擊累積穩定嗎？ | hijack_score PID 衰減率穩定性 | `_update_riverbed` PID |
| 11 | 河床 | 張力 | 什麼條件觸發 session 級警報？ | HWM 閾值 + crescendo 偵測 + sawtooth 偵測 | `check()` 三檢查 |
| 12 | 河床 | 動平 | session 防禦該收還是放？ | PID controller output（正=收，負=放） | `PIDController.update()` |
| 13 | 張力 | 河床 | persona drift 閾值穩定嗎？ | 需 6+ turns 才啟動，避免噪音 | `_update_persona_drift` |
| 14 | 張力 | 張力 | 什麼觸發 session 級模式切換？ | crescendo slope>0.05 / sawtooth variance>0.02 / persona drift>0.75 | 三偵測器 |
| 15 | 張力 | 動平 | session 敏感度該增還是減？ | Kalman estimator: FN→增，FP→減 | `SessionEstimator` |
| 16 | 動平 | 河床 | defense posture 穩定嗎？ | cooldown=10 防止振盪 | `DynBal._cooldown` |
| 17 | 動平 | 張力 | 什麼觸發 posture 切換？ | 連續 block→DEFENSIVE / clean streak→EFFICIENT | `observe_result()` |
| 18 | 動平 | 動平 | posture 該往哪調？ | threshold_mult = posture_mult × pid_mult，clamp [0.5, 1.5] | `get_threshold_multiplier()` |

## 大尺度（per-domain，領域規律 — 發現一次，全場景通用）

| # | 被控 | 透鏡 | 問題 | 映射 | 實作位置 |
|---|------|------|------|------|---------|
| 19 | 河床 | 河床 | AI 防禦的「穩定度」是什麼？ | 累積攻擊頻率 = multi-turn 模式穩定度 | `hijack_score` 概念 |
| 20 | 河床 | 張力 | 什麼條件下穩定度定義會變？ | 新攻擊類型出現（如 many-shot, skeleton key） | attack template bank 擴展 |
| 21 | 河床 | 動平 | 穩定度量化成什麼單位？ | B = (ΔE_atk/ΔE_nrm) × R × S（方向性河床公式） | `embedding_riverbed.py` |
| 22 | 張力 | 河床 | 觸發信號跨場景穩定嗎？ | embedding max-sim 跨語言穩定（KO 0.608→1.0） | max-sim vs centroid 驗證 |
| 23 | 張力 | 張力 | AI 防禦的觸發條件本身是什麼？ | **兩顆按鈕**：不問「是攻擊嗎」問「是安全嗎」 | Monitor Brain 設計哲學 |
| 24 | 張力 | 動平 | 觸發該往哪個方向演化？ | 加模板擴覆蓋面，不是收緊閾值 | normal/attack template banks |
| 25 | 動平 | 河床 | 防禦策略有哪些選項？ | L0(regex)+L1(embed)+L2(multi-turn)+L3a(LLM)+L3b(Monitor)+L5(output) | 六層管線 |
| 26 | 動平 | 張力 | 什麼觸發策略層級演化？ | 新攻擊類別突破所有層 → 加層或改層 | 架構迭代（v0.3→v0.4→v0.5） |
| 27 | 動平 | 動平 | 策略的雙向邊界在哪？ | 左界=全擋(fail-closed) / 右界=全放(fail-open) / **雙腦=身分樁+無記憶** | Two-Button + Dual-Brain |

---

## 驗證結果（2026-04-01）

**27/27 全格 ✅ 已實作且通過代碼驗證。**

| 格 | 狀態 | 關鍵實作位置 |
|----|------|-------------|
| 1 | ✅ | `embedding_riverbed.py:279` Shannon entropy on 4-dim |
| 2 | ✅ | `embedding_riverbed.py:453` is_suspect → L3 |
| 3 | ✅ | `embedding_riverbed.py:340` MicroPosture 0.7/1.0/1.3 |
| 4 | ✅ | `embedding_riverbed.py:310` sigmoid mapping |
| 5 | ✅ | `embedding_riverbed.py:315` h_norm→adjustment |
| 6 | ✅ | `embedding_riverbed.py:345` bidirectional+cooldown |
| 7 | ✅ | `dynamic_balance.py:188` deterministic routing |
| 8 | ✅ | `dynamic_balance.py:202` encoding/multilingual/multi-turn/boundary |
| 9 | ✅ | `dynamic_balance.py:39` DefensePath enum |
| 10 | ✅ | `riverbed.py:221` PID decay on hijack_score |
| 11 | ✅ | `riverbed.py:381` HWM+crescendo+sawtooth |
| 12 | ✅ | `dynamic_balance.py:50` PIDController |
| 13 | ✅ | `riverbed.py:240` 6+ turns guard |
| 14 | ✅ | `riverbed.py:169-177` all threshold values |
| 15 | ✅ | `dynamic_balance.py:99` Kalman SessionEstimator |
| 16 | ✅ | `dynamic_balance.py:243` cooldown=10 |
| 17 | ✅ | `dynamic_balance.py:290` consecutive blocks/clean streak |
| 18 | ✅ | `dynamic_balance.py:305` posture×pid, clamp [0.5,1.5] |
| 19-21 | ✅ | `embedding_riverbed.py:427` B = ΔE_ratio × R × S |
| 22 | ✅ | `embedding_riverbed.py:260` max-sim not centroid |
| 23 | ✅ | `agent.py:176` Two-Button + Monitor Brain |
| 24 | ✅ | `embedding_riverbed.py:51` expandable template banks |
| 25 | ✅ | `agent.py:9` L0.pre→L0→L1→L2→L3a→L3b→L4→L5 |
| 26 | ✅ | v0.3→v0.4→v0.5 evolution trail |
| 27 | ✅ | `agent.py:269,351,377,407` fail-closed + dual-brain |
