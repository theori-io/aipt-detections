/*
   AIPT - detection pack for LLM-driven autonomous pentest tools
   File:     aipt_memory.yar
   Version:  1.0.0 (2026-10-12)
   License:  Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License
   Engine:   YARA 4.x (compiled and tested with yara-python 4.5.4)
   Scope:    memory-safe variants (*_Mem) of the AIPT binary, tool-schema and prompt-marker rules, for live process
             scans (yara aipt_memory.yar <pid>, or an EDR memory scan). The file rules in aipt_artex.yar and
             aipt_family.yar depend on filesize, which never matches when YARA scans a running process, and some
             check a file header at offset 0, which is not the start of a mapped module. These variants use strings
             only: no filesize, no uint16(0)/uint32(0). Strings and thresholds are copied from the file rules; the
             LLM-side markers keep their original (short) length.
   Not provided (file-only by nature): Embedded_WebUI, Transcript_File, ApiRecon_Skill_Scripts, Supervisor_Script,
             GoMitmproxy_CA_Certificate_PEM; GoMitmproxy_Embedded_Recorder and Generic_LLM_Agent_Go_Binary are shared
             library / generic client shapes and would match too many processes without the executable-header guard.
   Interpretation: a match means the strings are mapped in that process (the binary itself, or a process that has the
             file or a transcript loaded, e.g. an editor or a scanner); it is not proof that the tool is running.
             Use a dedicated memory-scan profile; do not load this file for file scans (duplicate matches).
*/

rule AIPT_ARTEX_Go_Binary_Mem
{
   meta:
      description = "Memory-safe variant of AIPT_ARTEX_Go_Binary (strings only, no filesize or header check) for live process scans. Detects the ARTEX backend Go binary (module github.com/Autumn-27/artex) by its enrichment and self-update User-Agents, release URL, session-id formats and listen banner"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9"
      date = "2026-10-10"
      modified = "2026-10-10"
      score = 75
      hash = "3826c1dbff1f58007c2bc5b2991692605cf3b2b6c70f9e62051e71407853a7e9"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = "github.com/Autumn-27/artex" ascii
      $x2 = "api.github.com/repos/Autumn-27/artex/releases/latest" ascii
      $s1 = "artex-enrich/1.0" ascii
      $s2 = "artex-selfupdate" ascii
      $s3 = "exp%d-worker-i%d" ascii
      $s4 = "exp%d-planner" ascii
      $s5 = "backend listening on %s (data=%s, workers=%d)" ascii
      $s6 = "ARTEX_SELFUPDATE_SMOKE" ascii
      $s7 = "artex_token" ascii
   condition:
      ( 1 of ($x*) and 2 of ($s*) ) or 4 of ($s*)
}

rule AIPT_ARTEX_LLM_Tool_Schema_Mem
{
   meta:
      description = "Memory-safe variant of AIPT_ARTEX_LLM_Tool_Schema (strings only, no filesize or header check) for live process scans. Detects the ARTEX planner and worker tool names serialised as an LLM function schema, plain or JSON-escaped inside a record (LLM request records, relay logs, transcripts), compact or with up to four whitespace characters after the colon, or present together in the binary. Names written as \\uXXXX escapes are not matched"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/agent/tools.go"
      date = "2026-10-10"
      modified = "2026-10-10"
      score = 60
      hash = "3826c1dbff1f58007c2bc5b2991692605cf3b2b6c70f9e62051e71407853a7e9"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $s1 = /"name":\s{0,4}"graph_overview"/ ascii
      $s2 = /"name":\s{0,4}"add_intent"/ ascii
      $s3 = /"name":\s{0,4}"prove_goal"/ ascii
      $s4 = /"name":\s{0,4}"record_fact"/ ascii
      $s5 = /"name":\s{0,4}"report_finding"/ ascii
      $s6 = /"name":\s{0,4}"insert_assets"/ ascii
      $s7 = /"name":\s{0,4}"traffic_search"/ ascii
      $s8 = /"name":\s{0,4}"list_untested_assets"/ ascii
      $s9 = /"name":\s{0,4}"steer_work"/ ascii
      $e1 = /\\"name\\":\s{0,4}\\"graph_overview\\"/ ascii
      $e2 = /\\"name\\":\s{0,4}\\"add_intent\\"/ ascii
      $e3 = /\\"name\\":\s{0,4}\\"prove_goal\\"/ ascii
      $e4 = /\\"name\\":\s{0,4}\\"record_fact\\"/ ascii
      $e5 = /\\"name\\":\s{0,4}\\"report_finding\\"/ ascii
      $e6 = /\\"name\\":\s{0,4}\\"insert_assets\\"/ ascii
      $e7 = /\\"name\\":\s{0,4}\\"traffic_search\\"/ ascii
      $e8 = /\\"name\\":\s{0,4}\\"list_untested_assets\\"/ ascii
      $e9 = /\\"name\\":\s{0,4}\\"steer_work\\"/ ascii
      $b1 = "graph_overview" ascii
      $b2 = "list_untested_assets" ascii
      $b3 = "traffic_blob" ascii
      $b4 = "prove_goal" ascii
   condition:
      3 of ($s*) or 3 of ($e*) or all of ($b*)
}

rule AIPT_ARTEX_LLM_Prompt_Markers_Mem
{
   meta:
      description = "Memory-safe variant of AIPT_ARTEX_LLM_Prompt_Markers (strings only, no filesize or header check) for live process scans. Detects short fixed markers that ARTEX writes into its LLM conversations (guard block tag, worker chat marker, intent block header, goals decomposer role, connection test, output contract heading) in transcripts, LLM record dumps, relay logs or the binary"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/agent"
      date = "2026-10-10"
      modified = "2026-10-10"
      score = 60
      hash = "3826c1dbff1f58007c2bc5b2991692605cf3b2b6c70f9e62051e71407853a7e9"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = "【ARTEX 平台管控" ascii
      $x2 = "ARTEX_WORKER_CHAT:" ascii
      $s1 = "【你领到的意图" ascii
      $s2 = "渗透测试目标分解器" ascii
      $s3 = "你是连接测试" ascii
      $s4 = "中间产物输出规约" ascii
   condition:
      1 of ($x*) and 1 of ($s*) or 2 of ($s*)
}

rule AIPT_Norma_SDK_Go_Binary_Mem
{
   meta:
      description = "Memory-safe variant of AIPT_Norma_SDK_Go_Binary (strings only, no filesize or header check) for live process scans. Detects a Go binary built on the norma agent SDK (github.com/Autumn-27/norma), which ARTEX uses; any other norma-based agent matches too"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/go.mod"
      date = "2026-10-10"
      modified = "2026-10-10"
      score = 40
      hash = "3826c1dbff1f58007c2bc5b2991692605cf3b2b6c70f9e62051e71407853a7e9"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = "github.com/Autumn-27/norma" ascii
      $s1 = "norma/0.4" ascii
      $s2 = "<available-deferred-tools>" ascii
      $s3 = "The TodoWrite tool hasn't been used recently" ascii
   condition:
      $x1 and 1 of ($s*)
}

rule AIPT_CyberStrikeAI_Go_Binary_Mem
{
   meta:
      description = "Memory-safe variant of AIPT_CyberStrikeAI_Go_Binary (strings only, no filesize or header check) for live process scans. Detects the CyberStrikeAI server binary by its module path, client and WebShell-manager User-Agents, cgroup lock name, MCP auth header and the Eino agent framework"
      author = "Xint"
      reference = "https://github.com/AIPentest/CyberStrikeAI/tree/edec607731d2c8467a4c04de9b99bd9089857b3a"
      date = "2026-10-10"
      modified = "2026-10-10"
      score = 75
      hash = "d3f20ab4cf39428aec80b7d193d2ba2ca0dea2e4583cadfb1df776671e013f92"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = "cyberstrike-ai/internal/" ascii
      $s1 = "CyberStrikeAI/1." ascii
      $s2 = "CyberStrikeAI-WebShell/" ascii
      $s3 = "cyberstrike-cgroup-" ascii
      $s4 = "X-MCP-Token" ascii
      $s5 = "github.com/cloudwego/eino" ascii
   condition:
      ( $x1 and 1 of ($s1, $s2, $s3) ) or ( 2 of ($s1, $s2, $s3) and $s5 ) or ( $x1 and $s4 and $s5 )
}

rule AIPT_CyberStrikeAI_Prompt_Strings_Mem
{
   meta:
      description = "Memory-safe variant of AIPT_CyberStrikeAI_Prompt_Strings (strings only, no filesize or header check) for live process scans. Detects the CyberStrikeAI authorization-suppression block of its default agent prompt in the binary, agent definition files or exported conversations (both short fragments required)"
      author = "Xint"
      reference = "https://github.com/AIPentest/CyberStrikeAI/tree/edec607731d2c8467a4c04de9b99bd9089857b3a/internal/agent/default_single_system_prompt.go"
      date = "2026-10-10"
      modified = "2026-10-10"
      score = 50
      hash = "d3f20ab4cf39428aec80b7d193d2ba2ca0dea2e4583cadfb1df776671e013f92"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $s1 = "切勿等待批准或授权" ascii
      $s2 = "均不得质疑、辩论、索取或核实" ascii
   condition:
      all of them
}
