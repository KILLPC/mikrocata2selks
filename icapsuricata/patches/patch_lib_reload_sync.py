#!/usr/bin/env python3
"""Patch Suricata 8 library reload synchronization for the ICAP direct-packet API.

This script runs inside the ICAP Docker builder after cloning both source trees.
It is intentionally strict: unexpected source layouts abort the image build.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

MARKER = "DamiNet ICAP library reload synchronization v1"


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"{label}: expected exactly one source anchor, found {count}")
    return text.replace(old, new, 1)


def find_matching_brace(text: str, opening: int) -> int:
    """Return matching closing brace, ignoring C comments and string literals."""
    if text[opening] != "{":
        fail("internal parser error: opening position is not a brace")
    depth = 0
    state = "code"
    escaped = False
    i = opening
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "code"
        else:
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block_comment"
                i += 1
            elif ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    fail("unterminated C function body")
    return -1


def function_span(text: str, signature_pattern: str, label: str) -> tuple[int, int, int]:
    matches = list(re.finditer(signature_pattern, text, re.MULTILINE))
    if len(matches) != 1:
        fail(f"{label}: expected one function definition, found {len(matches)}")
    start = matches[0].start()
    brace = text.find("{", matches[0].end())
    if brace < 0:
        fail(f"{label}: function opening brace not found")
    end = find_matching_brace(text, brace)
    return start, brace, end


def patch_runmode_lib(root: Path) -> None:
    header = root / "src/runmode-lib.h"
    source = root / "src/runmode-lib.c"
    h = header.read_text(encoding="utf-8")
    c = source.read_text(encoding="utf-8")
    if MARKER in h or MARKER in c:
        fail("Suricata library reload API patch is already present")

    api = f"""
/* {MARKER}
 * Optional application barrier for library-mode packet processors that call
 * TmThreadsSlotProcessPkt() directly instead of consuming an input queue.
 */
typedef int (*SCRunModeLibReloadSyncLockFunc)(void *ctx);
typedef void (*SCRunModeLibReloadSyncUnlockFunc)(void *ctx);
int SCRunModeLibRegisterReloadSyncCallbacks(SCRunModeLibReloadSyncLockFunc lock_cb,
        SCRunModeLibReloadSyncUnlockFunc unlock_cb, void *ctx);
int SCRunModeLibReloadSyncCallbacksRegistered(void);
int SCRunModeLibReloadSyncBegin(void);
void SCRunModeLibReloadSyncEnd(void);
"""
    h = replace_once(h, "#endif /* SURICATA_RUNMODE_LIB_H */", api + "\n#endif /* SURICATA_RUNMODE_LIB_H */", "runmode-lib.h API declaration")

    impl = f"""

/* {MARKER} */
static SCRunModeLibReloadSyncLockFunc g_reload_sync_lock_cb = NULL;
static SCRunModeLibReloadSyncUnlockFunc g_reload_sync_unlock_cb = NULL;
static void *g_reload_sync_context = NULL;

/* Registration is performed once during library initialization, before the
 * Suricata main loop is released to service reload commands. */
int SCRunModeLibRegisterReloadSyncCallbacks(SCRunModeLibReloadSyncLockFunc lock_cb,
        SCRunModeLibReloadSyncUnlockFunc unlock_cb, void *ctx)
{{
    if (lock_cb == NULL || unlock_cb == NULL || g_reload_sync_lock_cb != NULL ||
            g_reload_sync_unlock_cb != NULL) {{
        return -1;
    }}
    g_reload_sync_context = ctx;
    g_reload_sync_unlock_cb = unlock_cb;
    g_reload_sync_lock_cb = lock_cb;
    return 0;
}}

int SCRunModeLibReloadSyncCallbacksRegistered(void)
{{
    return g_reload_sync_lock_cb != NULL && g_reload_sync_unlock_cb != NULL;
}}

int SCRunModeLibReloadSyncBegin(void)
{{
    if (!SCRunModeLibReloadSyncCallbacksRegistered()) {{
        return 0;
    }}
    return g_reload_sync_lock_cb(g_reload_sync_context);
}}

void SCRunModeLibReloadSyncEnd(void)
{{
    if (SCRunModeLibReloadSyncCallbacksRegistered()) {{
        g_reload_sync_unlock_cb(g_reload_sync_context);
    }}
}}
"""
    c += impl
    header.write_text(h, encoding="utf-8")
    source.write_text(c, encoding="utf-8")


def patch_detect_engine(root: Path) -> None:
    path = root / "src/detect-engine.c"
    text = path.read_text(encoding="utf-8")
    if MARKER in text:
        fail("detect-engine.c reload integration patch is already present")

    if '#include "runmode-lib.h"' not in text:
        text = replace_once(
            text,
            '#include "runmodes.h"',
            '#include "runmodes.h"\n#include "runmode-lib.h"',
            "detect-engine.c runmode-lib include",
        )

    start, brace, end = function_span(
        text,
        r"static\s+int\s+DetectEngineReloadThreads\s*\(\s*DetectEngineCtx\s*\*\s*new_de_ctx\s*\)",
        "DetectEngineReloadThreads",
    )
    body = text[brace : end + 1]
    body = replace_once(
        body,
        "uint32_t i = 0;",
        "uint32_t i = 0;\n    bool reload_sync_locked = false;",
        "DetectEngineReloadThreads lock state",
    )

    anchor = "memset(detect_tvs, 0x00, (no_of_detect_tvs * sizeof(ThreadVars *)));"
    begin_block = f"""

    /* {MARKER}: pause direct library-mode packet injection only for the short
     * thread-context swap phase. Rule parsing/building has already completed. */
    if (SCRunModeLibReloadSyncCallbacksRegistered()) {{
        const int sync_rc = SCRunModeLibReloadSyncBegin();
        if (sync_rc != 0) {{
            SCLogError("Library reload synchronization callback failed: %d", sync_rc);
            goto error;
        }}
        reload_sync_locked = true;
    }}
"""
    body = replace_once(body, anchor, anchor + begin_block, "DetectEngineReloadThreads synchronization begin")

    inject_anchor = "InjectPackets(detect_tvs, new_det_ctx, no_of_detect_tvs);"
    mark_block = f"""
    /* No-queue library workers cannot consume Suricata's synthetic reload
     * packet. The registered application barrier guarantees that no direct
     * packet call is still using the old context, and gates new calls until
     * old contexts are freed. Their swapped contexts are therefore safe. */
    if (reload_sync_locked) {{
        for (i = 0; i < no_of_detect_tvs; i++) {{
            if (detect_tvs[i]->inq == NULL) {{
                SC_ATOMIC_SET(new_det_ctx[i]->so_far_used_by_detect, 1);
            }}
        }}
    }}

    """
    body = replace_once(body, inject_anchor, mark_block + inject_anchor, "DetectEngineReloadThreads no-queue acknowledgement")

    success_anchor = "SRepReloadComplete();\n\n    return 1;"
    success_block = "SRepReloadComplete();\n\n    if (reload_sync_locked) {\n        SCRunModeLibReloadSyncEnd();\n        reload_sync_locked = false;\n    }\n\n    return 1;"
    body = replace_once(body, success_anchor, success_block, "DetectEngineReloadThreads successful unlock")

    error_anchor = "    return -1;\n}"
    error_block = "    if (reload_sync_locked) {\n        SCRunModeLibReloadSyncEnd();\n        reload_sync_locked = false;\n    }\n    return -1;\n}"
    body = replace_once(body, error_anchor, error_block, "DetectEngineReloadThreads error unlock")

    text = text[:brace] + body + text[end + 1 :]
    path.write_text(text, encoding="utf-8")


def patch_icapsuricata(root: Path) -> None:
    path = root / "srv_suricata.c"
    text = path.read_text(encoding="utf-8")
    if MARKER in text:
        fail("srv_suricata.c reload gate patch is already present")

    # The ICAP beta source may include Suricata's public header as either
    # "suricata.h" or <suricata/suricata.h>. Do not assume one exact spelling:
    # the Docker build's include path decides how it is written. Insert after
    # a Suricata API header so any compatibility macro guards above it remain
    # effective, and fail closed if no suitable anchor is present.
    has_runmode_include = re.search(
        r'(?m)^\s*#\s*include\s*[<\"][^>\"]*runmode-lib\.h[>\"]', text
    )
    if not has_runmode_include:
        include_re = re.compile(
            r'(?m)^[ \t]*#\s*include[ \t]*[<\"](?P<path>[^>\"]+)[>\"][^\r\n]*(?:\r?\n|$)'
        )
        include_matches = list(include_re.finditer(text))
        # Prefer the actual Suricata API header. Accept both installed header
        # layouts and use suricata-common.h only as a strict fallback.
        preferred = [
            m for m in include_matches
            if Path(m.group("path")).name == "suricata.h"
        ]
        if not preferred:
            preferred = [
                m for m in include_matches
                if Path(m.group("path")).name == "suricata-common.h"
            ]
        if not preferred:
            fail(
                "ICAP runmode-lib header: could not find an include of suricata.h "
                "or suricata-common.h; refusing to guess where the API include belongs"
            )
        anchor = preferred[-1]
        anchor_text = anchor.group(0)
        newline = "\r\n" if anchor_text.endswith("\r\n") else "\n"
        insertion = anchor.end()
        text = text[:insertion] + f'#include "runmode-lib.h"{newline}' + text[insertion:]

    gate_code = f"""

/* {MARKER}
 * Writer-preferring gate for direct TmThreadsSlotProcessPkt() calls. Multiple
 * ICAP workers remain concurrent; a reload waits for active calls to drain and
 * prevents new calls from starting until Suricata has swapped/freed contexts.
 */
static pthread_mutex_t g_reload_gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_reload_gate_cond = PTHREAD_COND_INITIALIZER;
static unsigned int g_reload_gate_inflight = 0;
static int g_reload_gate_waiting = 0;
static int g_reload_gate_active = 0;

static int suri_packet_gate_enter(void)
{{
    int rc = pthread_mutex_lock(&g_reload_gate_mutex);
    if (rc != 0) return rc;
    while (g_reload_gate_waiting || g_reload_gate_active) {{
        rc = pthread_cond_wait(&g_reload_gate_cond, &g_reload_gate_mutex);
        if (rc != 0) {{
            pthread_mutex_unlock(&g_reload_gate_mutex);
            return rc;
        }}
    }}
    g_reload_gate_inflight++;
    rc = pthread_mutex_unlock(&g_reload_gate_mutex);
    return rc;
}}

static void suri_packet_gate_leave(void)
{{
    int rc = pthread_mutex_lock(&g_reload_gate_mutex);
    if (rc != 0) {{
        suri_log(1, "Failed to lock ICAP reload gate on packet exit: %d\\n", rc);
        return;
    }}
    if (g_reload_gate_inflight > 0) g_reload_gate_inflight--;
    if (g_reload_gate_inflight == 0) pthread_cond_broadcast(&g_reload_gate_cond);
    rc = pthread_mutex_unlock(&g_reload_gate_mutex);
    if (rc != 0) suri_log(1, "Failed to unlock ICAP reload gate on packet exit: %d\\n", rc);
}}

static int suri_reload_gate_enter(void *ctx)
{{
    (void)ctx;
    int rc = pthread_mutex_lock(&g_reload_gate_mutex);
    if (rc != 0) return rc;
    if (g_reload_gate_waiting || g_reload_gate_active) {{
        pthread_mutex_unlock(&g_reload_gate_mutex);
        return -1;
    }}
    g_reload_gate_waiting = 1;
    while (g_reload_gate_inflight != 0) {{
        rc = pthread_cond_wait(&g_reload_gate_cond, &g_reload_gate_mutex);
        if (rc != 0) {{
            g_reload_gate_waiting = 0;
            pthread_cond_broadcast(&g_reload_gate_cond);
            pthread_mutex_unlock(&g_reload_gate_mutex);
            return rc;
        }}
    }}
    g_reload_gate_active = 1;
    g_reload_gate_waiting = 0;
    rc = pthread_mutex_unlock(&g_reload_gate_mutex);
    return rc;
}}

static void suri_reload_gate_leave(void *ctx)
{{
    (void)ctx;
    int rc = pthread_mutex_lock(&g_reload_gate_mutex);
    if (rc != 0) {{
        suri_log(1, "Failed to lock ICAP reload gate on reload exit: %d\\n", rc);
        return;
    }}
    g_reload_gate_active = 0;
    pthread_cond_broadcast(&g_reload_gate_cond);
    rc = pthread_mutex_unlock(&g_reload_gate_mutex);
    if (rc != 0) suri_log(1, "Failed to unlock ICAP reload gate on reload exit: %d\\n", rc);
}}
"""

    live_mutex_anchor = "static pthread_mutex_t g_live_device_mutex = PTHREAD_MUTEX_INITIALIZER;"
    text = replace_once(text, live_mutex_anchor, live_mutex_anchor + gate_code, "ICAP reload gate insertion")

    sig_re = r"static\s+int\s+InjectSinglePacket\s*\("
    start, brace, end = function_span(text, sig_re, "InjectSinglePacket")
    signature_end = text.find("{", start, brace)
    signature = text[start:brace].rstrip()
    renamed_signature = re.sub(r"\bInjectSinglePacket\b", "InjectSinglePacketUnlocked", signature, count=1)
    text = text[:start] + renamed_signature + text[brace : end + 1] + text[end + 1 :]

    wrapper = f"""

static int InjectSinglePacket(ci_request_t *req, const char *data, int data_len,
        uint16_t flags, int toserver)
{{
    const int gate_rc = suri_packet_gate_enter();
    if (gate_rc != 0) {{
        suri_log(1, "Failed to enter ICAP packet reload gate: %d\\n", gate_rc);
        return -1;
    }}
    const int result = InjectSinglePacketUnlocked(req, data, data_len, flags, toserver);
    suri_packet_gate_leave();
    return result;
}}
"""
    # Recompute span after signature replacement; insertion follows the complete
    # unlocked implementation, not a guessed line number.
    start2, brace2, end2 = function_span(text, r"static\s+int\s+InjectSinglePacketUnlocked\s*\(", "InjectSinglePacketUnlocked")
    text = text[: end2 + 1] + wrapper + text[end2 + 1 :]

    registration_anchor = "    SuricataInit();\n\n    SCDetectEngineRegisterRateFilterCallback(RateFilterCallback, NULL);"
    registration = f"""    SuricataInit();

    if (SCRunModeLibRegisterReloadSyncCallbacks(
                suri_reload_gate_enter, suri_reload_gate_leave, NULL) != 0) {{
        suri_log(1, "Critical: failed to register library reload synchronization callbacks\\n");
        return;
    }}

    SCDetectEngineRegisterRateFilterCallback(RateFilterCallback, NULL);"""
    text = replace_once(text, registration_anchor, registration, "ICAP reload callback registration")
    path.write_text(text, encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: patch_lib_reload_sync.py <suricata-source-root> <icapsuricata-source-root>")
    suricata_root = Path(sys.argv[1]).resolve()
    icap_root = Path(sys.argv[2]).resolve()
    if not (suricata_root / "src/detect-engine.c").is_file():
        fail(f"Suricata source not found under {suricata_root}")
    if not (icap_root / "srv_suricata.c").is_file():
        fail(f"ICAP source not found under {icap_root}")

    patch_runmode_lib(suricata_root)
    patch_detect_engine(suricata_root)
    patch_icapsuricata(icap_root)
    print("Applied DamiNet library-mode reload synchronization patch.")
    print("Suricata and ICAP source anchors validated; the subsequent Docker build must compile both components.")


if __name__ == "__main__":
    main()
