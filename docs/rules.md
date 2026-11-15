# Regras de detecção

Cada regra é uma função em `src/rules.py` que recebe o conjunto de dados (RH, contas, grupos,
memberships, revisões) e a configuração, e devolve uma tabela de achados. Severidades e pontos de risco:
`critical = 4`, `high = 3`, `medium = 2`, `low = 1` (definidos em `src/policy.py`).

## Modelo de dados (sintético)

| Tabela | Conteúdo |
|---|---|
| `employees.csv` | Registro do RH: departamento, cargo, gestor, admissão, desligamento, status (`active`, `on_leave`, `terminated`) |
| `accounts.csv` | Contas do diretório: tipo (`user` ou `service`), habilitada, último logon, data de desativação, responsável (contas de serviço) |
| `groups.csv` | Grupos, nível de privilégio (`low`, `medium`, `high`, `critical`) e área dona |
| `memberships.csv` | Quem pertence a qual grupo, desde quando e quem concedeu |
| `reviews.csv` | Campanhas de revisão de acessos privilegiados: revisor, prazo, decisão (`approved`, `revoked`, `pending`) |

## As regras

### R01, `orphan_account`: conta ativa de desligado ou sem vínculo no RH
- **Lógica:** conta de usuário habilitada cujo colaborador está `terminated`, ou que não tem registro no RH.
- **Severidade:** `critical` se houve logon **depois** do desligamento; `high` nos demais casos.
- **Por que importa:** é o caminho clássico de acesso indevido (ex-colaborador, conta de terceiro esquecida).
- **Ação:** desabilitar, investigar atividade pós-desligamento, remover acessos.

### R02, `dormant_account`: conta ativa sem logon recente
- **Lógica:** conta habilitada sem logon há mais de `--dormant-days` (padrão 90). Pessoas em licença
  (`on_leave`) são ignoradas, porque a inatividade é esperada; desligados caem na R01.
- **Severidade:** `high` se a conta tem acesso privilegiado; `medium` nos demais casos.
- **Ação:** confirmar com o gestor ou responsável; desabilitar se não for mais usada.

### R03, `sod_conflict`: segregação de funções
- **Lógica:** a mesma conta possui os dois grupos de um par conflitante definido em `policy.SOD_CONFLICTS`
  (criar + aprovar contas a pagar; iniciar + aprovar pagamentos; deploy em produção + admin de banco;
  admin de identidades + leitura de logs de auditoria).
- **Severidade:** definida por par (pagamentos = `critical`).
- **Ação:** remover um dos acessos ou documentar controle compensatório aprovado.

### R04, `cross_department_privilege`: privilégio em grupo de outra área
- **Lógica:** conta de usuário com acesso `high` ou `critical` a grupo cujo dono é outro departamento.
- **Severidade:** `high`.
- **Ação:** validar a justificativa de negócio com o dono do grupo.

### R05, `excessive_privileged_groups`: acúmulo de privilégios
- **Lógica:** conta em pelo menos `--privileged-threshold` (padrão 3) grupos privilegiados.
- **Severidade:** `medium` no limite, `high` acima dele.
- **Ação:** aplicar menor privilégio e separar contas administrativas das contas do dia a dia.

### R06, `unreviewed_privileged_access`: acesso privilegiado sem revisão recente
- **Lógica:** membership em grupo `high` ou `critical` sem revisão **concluída** (`approved` ou
  `revoked`) nos últimos `--review-window-days` (padrão 180).
- **Severidade:** `high` para grupos `critical`; `medium` para `high`.
- **Observação:** contas já marcadas como órfãs (R01) não geram R06, para evitar dupla contagem.

### R07, `revoked_not_removed`: revogação decidida e não executada
- **Lógica:** existe revisão com decisão `revoked`, mas a conta continua no grupo.
- **Severidade:** `high`.
- **Ação:** executar a revogação e guardar a evidência.

### R08, `overdue_review`: revisão atrasada
- **Lógica:** revisão `pending` com prazo vencido.
- **Severidade:** `low`; `medium` se o atraso é de 30 dias ou mais.
- **Ação:** escalar ao gestor do revisor.

### R09, `late_deprovisioning`: desativação tardia
- **Lógica:** conta desabilitada mais de `--deprovision-sla-days` (padrão 2) dias depois do desligamento.
- **Severidade:** `low`; `medium` acima de 7 dias.
- **Ação:** revisar o fluxo RH → TI.

### R10, `service_account_without_owner`: conta de serviço sem responsável
- **Lógica:** conta de serviço habilitada sem `owner_employee_id`.
- **Severidade:** `high` se tem acesso privilegiado; `medium` nos demais casos.
- **Ação:** definir um responsável ou desativar.

## Referências para estudo

Mapeamento aproximado, útil para conversar sobre o projeto em entrevistas. Confira sempre a versão
vigente de cada norma.

| Tema | ISO/IEC 27001:2022 (Anexo A) | Outros |
|---|---|---|
| Contas órfãs, desativação | 5.16 Gestão de identidades; 5.18 Direitos de acesso | CIS Controls v8: 5 (gestão de contas) |
| Segregação de funções | 5.3 Segregação de funções | NIST CSF 2.0: PR.AA |
| Acesso privilegiado, menor privilégio | 8.2 Direitos de acesso privilegiado | CIS Controls v8: 6 (gestão de controle de acesso) |
| Revisão periódica de acessos | 5.18 Direitos de acesso | NIST CSF 2.0: PR.AA |
