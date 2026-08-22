# ForgeBoss v0.7 — Cost-Optimized Debug Funnel + Repair Memory

This release changes the expensive retry pattern.

After a failed cycle ForgeBoss now performs a deterministic $0 debug funnel before another model call:
- classifies the failure;
- identifies up to 6 relevant files;
- caps focused source context at 42,000 characters;
- carries only the recent exact failure evidence;
- omits the large historical repair-lab and reference-pack payloads on focused retries;
- caps focused OpenAI repair output at 6,000 tokens;
- records failed failure signatures in local repair memory;
- supplies matching failed/proven history to later focused repairs;
- refuses another paid call if it cannot safely create the compact packet.

Validation remains local. The model is asked to fix the focused root cause, then existing acceptance gates decide whether the repair is real.

This does not claim that every focused call will cost a particular number of cents; actual API cost depends on model pricing, token usage and response length. The goal is to materially reduce repeated context and output compared with the previous ~438 KB strong-model repair packets.
