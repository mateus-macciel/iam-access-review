# Resumo da revisão de acessos — 13/11/2026

> Dados sintéticos (fictícios), gerados por `src/generate_data.py`.

## Visão geral

- Contas ativas analisadas: **378** (14 de serviço)
- Achados: **102**, em **78** contas (20.6% das contas ativas)
- Por severidade: critical **7** · high **42** · medium **38** · low **15**
- Cobertura da revisão de acessos privilegiados (últimos 180 dias): **92.0%** (103 de 112)
- Revisões pendentes e vencidas: **33**
- Tempo médio para desativar contas após o desligamento: **1.8 dias**

## Achados por regra

| Regra | Descrição | Qtde |
|---|---|---:|
| R01 | Conta ativa de colaborador desligado ou sem vínculo no RH | 8 |
| R02 | Conta ativa sem logon recente | 17 |
| R03 | Conflito de segregação de funções (SoD) | 10 |
| R04 | Acesso privilegiado a grupo de outra área | 12 |
| R05 | Conta com muitos grupos privilegiados | 3 |
| R06 | Acesso privilegiado sem revisão recente | 7 |
| R07 | Revisão decidiu revogar, mas o acesso continua | 3 |
| R08 | Revisão de acesso pendente além do prazo | 33 |
| R09 | Conta desabilitada depois do prazo após o desligamento | 6 |
| R10 | Conta de serviço sem responsável definido | 3 |

## Top 5 contas em risco

| Conta | Área | Pontos | Regras |
|---|---|---:|---|
| sergio.guimaraes | Tecnologia | 13 | R04, R05, R08 |
| svc-legacy-app | Tecnologia | 9 | R02, R06, R10 |
| rafaela.campos | Financeiro | 8 | R04, R06, R08 |
| svc-hr-export | RH | 8 | R02, R06, R10 |
| felipe.moreira | Tecnologia | 6 | R04, R05, R08 |

## Ações recomendadas

1. **Revisão de acesso pendente além do prazo** (33 achados): Escalar ao gestor do revisor e fixar um novo prazo.
2. **Conta ativa sem logon recente** (17 achados): Confirmar a necessidade com o gestor/responsável; desabilitar se não for mais usada.
3. **Acesso privilegiado a grupo de outra área** (12 achados): Validar a justificativa de negócio com o dono do grupo; remover se não houver.
4. **Conflito de segregação de funções (SoD)** (10 achados): Remover um dos dois acessos ou documentar controle compensatório aprovado.
