# AIPT detection pack

ARTEX, CyberStrikeAI, HexStrike-AI, PentAGI, Strix, Shannon, MetasploitMCP 등 LLM 기반 자율 침투 테스트 도구의 지문과 자동화 패턴을 탐지하는 룰 모음입니다.
상세 설명은 영문 [README.md](README.md), 배포 전 확인 사항은 [DEPLOYMENT.md](DEPLOYMENT.md), 룰별 근거와 상세 사항은 [RULES.md](RULES.md)를 참고하세요.

| 디렉터리 | 내용 | 대상 |
|---|---|---|
| `suricata/` | 룰 82개. 센서 위치별 4개 파일(대상 웹, 노출 콘솔, 운영자 이그레스, LLM 측) | IDS |
| `sigma/` | 탐지 룰 54개 + 상관 룰 8개, 변환 파이프라인 | SIEM |
| `yara/` | 파일 룰 13개, 프로세스 메모리용 변형 6개 | 호스트 파일, 프로세스 메모리 |
| `modsecurity/` | OWASP CRS v4 플러그인, 탐지 룰 24개 | WAF |
| `analytics/` | KQL, SPL 헌팅 쿼리와 상관 룰 등가 쿼리 | Splunk, Sentinel, Elastic |

## 공개 범위

공개본에는 룰, 변환 설정, KQL/SPL 쿼리와 문서만 포함합니다. 내부 Python 유틸리티, 테스트 코드, 픽스처 생성기, 재생용 설정, 실행 로그와 CI는 제외했습니다. [오탐 보고서](docs/fp-report.md)에는 측정 방법과 집계 결과를 남겼습니다.

## 배포 전 확인

정식 탐지에 사용하기 전에 내부 시험 환경 또는 제한된 비차단 구간에서 시험 운용하세요. 정상 트래픽, 승인된 보안 점검과 자동화 작업을 포함해 로그 필드 매핑, 오탐, 경보량, 자원 사용량과 서비스 영향을 확인해야 합니다. 경보 전용 적용도 경보 과다나 자원 사용량 증가를 일으킬 수 있습니다. 차단은 개별 룰 검토와 되돌리기 절차 확인 후 단계적으로 적용하세요.

탐지 결과는 도구 지문이나 자동화 패턴에 대한 신호입니다. AI 사용 여부, 악성 의도, 승인 여부 또는 공격 성공을 단독으로 입증하지 않습니다. 대상 웹서비스 측 WAF만으로 외부 공격자의 LLM 호출이나 프로세스를 관측할 수도 없습니다.

기본 배포는 관찰 전용입니다. Suricata 룰은 `alert`이고, ModSecurity 플러그인은 inbound 스위치 `9590015` 또는 outbound 스위치 `9590013`를 명시적으로 켜기 전까지 CRS anomaly score를 추가하지 않습니다. 기존 WAF의 CRS 보호를 해제하거나 전체 `SecRuleEngine`을 `DetectionOnly`로 바꾸지 마세요.

`block-eligible`은 개별 검토 대상이지 일괄 차단 권고가 아닙니다. SID `9500060`은 파일 재생 검증이 없어 차단 전환 목록에서 보류되어 있습니다. 범용 룰은 정상 자동화에도 반응하며, `web_aipt_*_base` 선택자는 상관분석 입력 전용이므로 단독 경보로 사용하지 마세요.

## 검증 범위

실제 엔진 테스트, 자체 Python 매처, Python 모사와 과거 랩 검증은 서로 다른 검증입니다. 영문 README의 `Validation` 절과 [오탐 보고서](docs/fp-report.md)는 제작자가 보고한 내부 검증 방법과 결과를 요약합니다. 하네스, 코퍼스와 실행 로그를 공개하지 않으므로 이 저장소만으로 해당 결과를 재현할 수는 없습니다. 합성 코퍼스의 측정값은 운영 환경의 오탐률을 보장하지 않습니다.

Kusto emulator 기능 테스트는 내부 검증 결과에 포함되지만, 운영 환경의 피크 부하는 측정하지 않았습니다. KQL을 운영 예약 경보에 사용하기 전에는 대상 환경에서 실행 결과와 쿼리 자원 사용량을 확인하세요. 다른 형식의 룰을 평가하는 데 Kusto 환경이 필요한 것은 아닙니다.

보고서 본문에 넣을 주의 문구는 [별도 문서](docs/report-deployment-notice.md)에 정리했습니다.

새로운 룰을 추가하거나 수정하려면 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요. 보안 관련 제보는 [SECURITY.md](SECURITY.md), 기타 문의는 contact@xint.io로 부탁드립니다.
