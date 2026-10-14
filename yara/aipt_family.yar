/*
   AIPT - detection pack for LLM-driven autonomous pentest tools
   File:     aipt_family.yar
   Version:  1.0.0 (2026-10-12)
   License:  Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License
   Engine:   YARA 4.x (compiled and tested with yara-python 4.5.4)
   Scope:    CyberStrikeAI v1.7.22 (edec607) and a generic Go LLM-agent hunting rule
   Release builds of these tools are stripped Go binaries (-trimpath -s -w), so the rules use read-only string
   literals (module paths, User-Agent constants, format strings) and never Go build IDs or symbol names.
   File scope: every rule here uses filesize, so it applies to files and to memory dumps saved as files, never to a
   live process scan. Memory-safe variants for live process scans are in aipt_memory.yar.
*/

rule AIPT_CyberStrikeAI_Go_Binary
{
   meta:
      description = "Detects the CyberStrikeAI server binary by its module path, client and WebShell-manager User-Agents, cgroup lock name, MCP auth header and the Eino agent framework"
      author = "Xint"
      reference = "https://github.com/AIPentest/CyberStrikeAI/tree/edec607731d2c8467a4c04de9b99bd9089857b3a"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 85
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
      (uint32(0) == 0x464c457f or uint16(0) == 0x5a4d or uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xbebafeca) and filesize < 300MB and
      ( ( $x1 and 1 of ($s1, $s2, $s3) ) or ( 2 of ($s1, $s2, $s3) and $s5 ) or ( $x1 and $s4 and $s5 ) )
}

rule AIPT_CyberStrikeAI_Prompt_Strings
{
   meta:
      description = "Detects the CyberStrikeAI authorization-suppression block of its default agent prompt in the binary, agent definition files or exported conversations (both short fragments required, raw UTF-8 or both JSON \\uXXXX-escaped)"
      author = "Xint"
      reference = "https://github.com/AIPentest/CyberStrikeAI/tree/edec607731d2c8467a4c04de9b99bd9089857b3a/internal/agent/default_single_system_prompt.go"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 60
      hash = "d3f20ab4cf39428aec80b7d193d2ba2ca0dea2e4583cadfb1df776671e013f92"
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $s1 = "切勿等待批准或授权" ascii
      $s2 = "均不得质疑、辩论、索取或核实" ascii
      // the same fragments as JSON \\uXXXX escapes (exports re-serialised with json.dumps ensure_ascii=True); hex either case
      $e1 = "\\u5207\\u52ff\\u7b49\\u5f85\\u6279\\u51c6\\u6216\\u6388\\u6743" ascii nocase
      $e2 = "\\u5747\\u4e0d\\u5f97\\u8d28\\u7591\\u3001\\u8fa9\\u8bba\\u3001\\u7d22\\u53d6\\u6216\\u6838\\u5b9e" ascii nocase
   condition:
      filesize < 300MB and ( all of ($s*) or all of ($e*) )
}

rule AIPT_Generic_LLM_Agent_Go_Binary
{
   meta:
      description = "Hunting rule for Go binaries that call an LLM API with function tools (chat-completions or messages path, provider header, tool-call fields); matches ARTEX, CyberStrikeAI and many benign LLM clients"
      author = "Xint"
      reference = "https://platform.openai.com/docs/api-reference/chat"
      date = "2026-10-09"
      modified = "2026-10-10"
      score = 30
      license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
   strings:
      $p1 = "/chat/completions" ascii
      $p2 = "/v1/messages" ascii
      $h1 = "anthropic-version" ascii
      $h2 = "x-api-key" ascii
      $t1 = "tool_calls" ascii
      $t2 = /"type":\s{0,4}"function"/ ascii
      $t3 = "tool_use_id" ascii
   condition:
      (uint32(0) == 0x464c457f or uint16(0) == 0x5a4d or uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xbebafeca) and filesize < 300MB and 1 of ($p*) and 1 of ($h*) and 2 of ($t*)
}
