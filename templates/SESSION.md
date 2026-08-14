# 交接文档 · SESSION

> 由 ai-context-ferry 自动生成 · 生成时间：{{generated_at}} · 源账号：{{source.account_id}}（平台：{{source.platform}}）

## 1. 项目背景
{{project_background}}

## 2. 关键决策与上下文
{{key_decisions}}

## 3. 进行中任务
{{in_progress}}

## 4. 遗留阻塞 / 风险
{{blockers}}

## 5. 下一步建议
{{next_steps}}

## 6. 资产清单（摘要）
| 资产 | 类型 | 重要度 | 可迁移 | 需重授权 |
|---|---|---|---|---|
{% for asset in assets -%}
| {{asset.name}} | {{asset.asset_type}} | {{asset.importance}} | {{asset.transferable}} | {{asset.reauth_required}} |
{% endfor %}

## 7. 凭据与脱敏说明
{{secret_summary}}
> 说明：被识别为敏感凭据的内容已从明文资产中抽出并单独处理；普通上下文内容保持明文可读，不强制加密。

---
*完整性校验：{{verification_summary}}*
*说明：凭证类资产（如集成连接）仅迁移元数据，需在新账号手动重新授权。*
