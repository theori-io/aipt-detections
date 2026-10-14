/*
   AIPT - detection pack for LLM-driven autonomous pentest tools
   File:     aipt_artex.yar
   Version:  1.0.0 (2026-10-12)
   License:  Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License
   Engine:   YARA 4.x (compiled and tested with yara-python 4.5.4)
   Scope:    ARTEX v0.3.15 (Autumn-27/ARTEX e6ec569) host artefacts, plus the norma SDK and go-mitmproxy components it embeds
   Release builds of these tools are stripped Go binaries (-trimpath -s -w), so the rules use read-only string
   literals (module paths, User-Agent constants, format strings) and never Go build IDs or symbol names.
   File scope: every rule here uses filesize (and some a file-header check at offset 0), so it applies to files and to
   memory dumps saved as files, never to a live process scan (filesize does not match there). Memory-safe variants
   for live process scans are in aipt_memory.yar.
*/

rule AIPT_ARTEX_Go_Binary
{
   meta:
      description = "Detects the ARTEX backend Go binary (module github.com/Autumn-27/artex) by its enrichment and self-update User-Agents, release URL, session-id formats and listen banner"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 85
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
      (uint32(0) == 0x464c457f or uint16(0) == 0x5a4d or uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xbebafeca) and filesize < 200MB and
      ( ( 1 of ($x*) and 2 of ($s*) ) or 4 of ($s*) )
}

rule AIPT_ARTEX_Embedded_WebUI
{
   meta:
      description = "Detects the ARTEX web console (embedded in the binary or as the exported Next.js site) by its HTML title, meta description, login and disclaimer strings and session cookie name"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/web/src/config/app-config.ts"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 75
      hash = "3826c1dbff1f58007c2bc5b2991692605cf3b2b6c70f9e62051e71407853a7e9"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $s1 = "自主渗透测试控制台" ascii
      $s2 = "LLM 驱动的自主渗透测试系统控制台" ascii
      $s3 = "请输入密码以继续使用 ARTEX" ascii
      $s4 = "ARTEX 使用须知与免责声明" ascii
      $s5 = "artex_token" ascii
   condition:
      filesize < 200MB and 2 of them
}

rule AIPT_ARTEX_LLM_Prompt_Markers
{
   meta:
      description = "Detects short fixed markers that ARTEX writes into its LLM conversations (guard block tag, worker chat marker, intent block header, goals decomposer role, connection test, output contract heading) in transcripts, LLM record dumps, relay logs or the binary; raw UTF-8 or JSON \\uXXXX-escaped"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/agent"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 70
      hash = "3826c1dbff1f58007c2bc5b2991692605cf3b2b6c70f9e62051e71407853a7e9"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = "【ARTEX 平台管控" ascii
      $x2 = "ARTEX_WORKER_CHAT:" ascii
      $s1 = "【你领到的意图" ascii
      $s2 = "渗透测试目标分解器" ascii
      $s3 = "你是连接测试" ascii
      $s4 = "中间产物输出规约" ascii
      // the same markers as JSON \\uXXXX escapes (json.dumps ensure_ascii=True: Python relays, proxies, SDK exports); hex either case
      $xe1 = "\\u3010ARTEX \\u5e73\\u53f0\\u7ba1\\u63a7" ascii nocase
      $se1 = "\\u3010\\u4f60\\u9886\\u5230\\u7684\\u610f\\u56fe" ascii nocase
      $se2 = "\\u6e17\\u900f\\u6d4b\\u8bd5\\u76ee\\u6807\\u5206\\u89e3\\u5668" ascii nocase
      $se3 = "\\u4f60\\u662f\\u8fde\\u63a5\\u6d4b\\u8bd5" ascii nocase
      $se4 = "\\u4e2d\\u95f4\\u4ea7\\u7269\\u8f93\\u51fa\\u89c4\\u7ea6" ascii nocase
   condition:
      filesize < 200MB and ( 1 of ($x*) and 1 of ($s*) or 2 of ($s*) )
}

rule AIPT_ARTEX_LLM_Tool_Schema
{
   meta:
      description = "Detects the ARTEX planner and worker tool names serialised as an LLM function schema, plain or JSON-escaped inside a record (LLM request records, relay logs, transcripts), compact or with up to four whitespace characters after the colon, or present together in the binary. Names written as \\uXXXX escapes are not matched"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/agent/tools.go"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 70
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
      filesize < 200MB and ( 3 of ($s*) or 3 of ($e*) or ( (uint32(0) == 0x464c457f or uint16(0) == 0x5a4d or uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xbebafeca) and all of ($b*) ) )
}

rule AIPT_ARTEX_Transcript_File
{
   meta:
      description = "Detects ARTEX agent transcripts and LLM record exports: JSON lines whose session_id has an ARTEX session name (exp<N>-worker-i<M>, -planner, -main, -main-s<K>, -goals, -compactor, -btw-<id>, or conv-<N>; the same list as the Sigma file rule file_event_lnx_artex_transcript_files) together with an ARTEX tool name"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/agent/worker.go"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 80
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = /"session_id":\s{0,4}"(exp[0-9]{1,9}-(worker-i[0-9]{1,9}|planner|main(-s[0-9]{1,9})?|goals|compactor|btw-[A-Za-z0-9_-]{1,64})|conv-[0-9]{1,19})"/ ascii
      $s1 = "record_fact" ascii
      $s2 = "prove_goal" ascii
      $s3 = "add_intent" ascii
      $s4 = "graph_overview" ascii
      $s5 = "report_finding" ascii
   condition:
      filesize < 500MB and not (uint32(0) == 0x464c457f or uint16(0) == 0x5a4d or uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xbebafeca) and $x1 and 1 of ($s*)
}

rule AIPT_ARTEX_ApiRecon_Skill_Scripts
{
   meta:
      description = "Detects the reference scripts of the ARTEX api-recon skill (harvest_static.py, spider_mpa.py, preload.js, runtime_harvest.js) by their User-Agent constants or preload globals"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/skills/api-recon/scripts"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 75
      hash = "9ab792fe7de3c9ae736228362aaed00051ea9c762503a27ce3188113e1fb5092"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = "Mozilla/5.0 (spa-api-recon)" ascii
      $x2 = "Mozilla/5.0 (spa-api-recon spider)" ascii
      $s1 = "__API_RECON_PRELOAD__" ascii
      $s2 = "__API_RECON_LOG__" ascii
      $s3 = "__API_RECON_ROUTES__" ascii
      $s4 = "__API_RECON_OBSERVE__" ascii
   condition:
      filesize < 1MB and ( 1 of ($x*) or 2 of ($s*) )
}

rule AIPT_ARTEX_Supervisor_Script
{
   meta:
      description = "Detects the ARTEX start.sh supervisor that relaunches the binary after a self-update (exit code 75)"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/start.sh"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 65
      hash = "60a83fa328b156f3cb7874950b638862c0719c1f9d6e5915b1181e4daebbce6c"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = "RESTART_CODE=75" ascii
      $s1 = "[artex]" ascii
      $s2 = "./artex" ascii
      $s3 = "ARTEX" ascii
      $s4 = "MAX_DELAY=60" ascii
   condition:
      filesize < 20KB and $x1 and 2 of ($s*)
}

rule AIPT_Norma_SDK_Go_Binary
{
   meta:
      description = "Detects a Go binary built on the norma agent SDK (github.com/Autumn-27/norma), which ARTEX uses; any other norma-based agent matches too"
      author = "Xint"
      reference = "https://github.com/CSharperMantle/Autumn-27-ARTEX/tree/e6ec56999175509551a1e43a3ee3b053d0941bd9/go.mod"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 50
      hash = "3826c1dbff1f58007c2bc5b2991692605cf3b2b6c70f9e62051e71407853a7e9"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = "github.com/Autumn-27/norma" ascii
      $s1 = "norma/0.4" ascii
      $s2 = "<available-deferred-tools>" ascii
      $s3 = "The TodoWrite tool hasn't been used recently" ascii
   condition:
      (uint32(0) == 0x464c457f or uint16(0) == 0x5a4d or uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xbebafeca) and filesize < 200MB and $x1 and 1 of ($s*)
}

rule AIPT_GoMitmproxy_Embedded_Recorder
{
   meta:
      description = "Detects a Go binary embedding go-mitmproxy together with its CA file names, as the ARTEX traffic recorder does; every go-mitmproxy consumer matches"
      author = "Xint"
      reference = "https://github.com/lqqyt2423/go-mitmproxy"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 40
      hash = "3826c1dbff1f58007c2bc5b2991692605cf3b2b6c70f9e62051e71407853a7e9"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $x1 = "lqqyt2423/go-mitmproxy" ascii
      $s1 = "mitmproxy-ca-cert.pem" ascii
      $s2 = "mitmproxy-ca.pem" ascii
   condition:
      (uint32(0) == 0x464c457f or uint16(0) == 0x5a4d or uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xbebafeca) and filesize < 200MB and $x1 and 1 of ($s*)
}

rule AIPT_GoMitmproxy_CA_Certificate_PEM
{
   meta:
      description = "Detects a PEM certificate whose DER name is O=mitmproxy, CN=mitmproxy encoded as PrintableString, the CA that go-mitmproxy generates (ARTEX writes it to data/traffic/_ca/). Matches the base64 body at all three alignments and across PEM line breaks; standalone go-mitmproxy CAs match too"
      author = "Xint"
      reference = "https://github.com/lqqyt2423/go-mitmproxy"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 40
      hash = "d4d603cf84c5d2c58f7c3906a64f8342abec750dfda30f191ad4a33c6696eb37"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $h1 = "-----BEGIN CERTIFICATE-----" ascii
      $n1 = /M\r?\n?R\r?\n?I\r?\n?w\r?\n?E\r?\n?A\r?\n?Y\r?\n?D\r?\n?V\r?\n?Q\r?\n?Q\r?\n?K\r?\n?E\r?\n?w\r?\n?l\r?\n?t\r?\n?a\r?\n?X\r?\n?R\r?\n?t\r?\n?c\r?\n?H\r?\n?J\r?\n?v\r?\n?e\r?\n?H\r?\n?k\r?\n?x\r?\n?E\r?\n?j\r?\n?A\r?\n?Q\r?\n?B\r?\n?g\r?\n?N\r?\n?V\r?\n?B\r?\n?A\r?\n?M\r?\n?T\r?\n?C\r?\n?W\r?\n?1\r?\n?p\r?\n?d\r?\n?G\r?\n?1\r?\n?w\r?\n?c\r?\n?m\r?\n?9\r?\n?4/
      $n2 = /E\r?\n?S\r?\n?M\r?\n?B\r?\n?A\r?\n?G\r?\n?A\r?\n?1\r?\n?U\r?\n?E\r?\n?C\r?\n?h\r?\n?M\r?\n?J\r?\n?b\r?\n?W\r?\n?l\r?\n?0\r?\n?b\r?\n?X\r?\n?B\r?\n?y\r?\n?b\r?\n?3\r?\n?h\r?\n?5\r?\n?M\r?\n?R\r?\n?I\r?\n?w\r?\n?E\r?\n?A\r?\n?Y\r?\n?D\r?\n?V\r?\n?Q\r?\n?Q\r?\n?D\r?\n?E\r?\n?w\r?\n?l\r?\n?t\r?\n?a\r?\n?X\r?\n?R\r?\n?t\r?\n?c\r?\n?H\r?\n?J\r?\n?v/
      $n3 = /x\r?\n?E\r?\n?j\r?\n?A\r?\n?Q\r?\n?B\r?\n?g\r?\n?N\r?\n?V\r?\n?B\r?\n?A\r?\n?o\r?\n?T\r?\n?C\r?\n?W\r?\n?1\r?\n?p\r?\n?d\r?\n?G\r?\n?1\r?\n?w\r?\n?c\r?\n?m\r?\n?9\r?\n?4\r?\n?e\r?\n?T\r?\n?E\r?\n?S\r?\n?M\r?\n?B\r?\n?A\r?\n?G\r?\n?A\r?\n?1\r?\n?U\r?\n?E\r?\n?A\r?\n?x\r?\n?M\r?\n?J\r?\n?b\r?\n?W\r?\n?l\r?\n?0\r?\n?b\r?\n?X\r?\n?B\r?\n?y\r?\n?b\r?\n?3\r?\n?h\r?\n?5/
   condition:
      filesize < 64KB and $h1 and 1 of ($n*)
}
