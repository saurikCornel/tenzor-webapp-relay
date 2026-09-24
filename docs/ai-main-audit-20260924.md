# Реестр изменений webapp-relay за 21–23.09.2026 (Europe/Moscow)

Интервал: [2026-09-21T00:00:00+03:00, 2026-09-24T00:00:00+03:00).
Репозиторий: `git@github.com:saurikCornel/tenzor-webapp-relay.git` (origin проверен). Назначенный SHA: `db35b4132667883184c7ebb2a1a383fb703f7cfe`.

## Итог
- `origin/main` = `db35b41…` — совпадает с назначенным SHA. Все коммиты периода уже в `origin/main`; сливать нечего.
- Локальная ветка `main` устарела (8472fd2, 3 коммита позади origin/main) — локальный указатель, не remote; не менять.
- Кандидаты: 29 remote-веток (см. `ai-main-candidates-20260924.tsv`, полнота: все `refs/remotes/origin/*` кроме HEAD/main): 9 равны main, 17 — предки main (0 своих коммитов, 3 позади), ни одной с уникальными коммитами. Конфликтов нет.

## Коммиты периода (в main)
| SHA | Дата | Тема | Файлы |
|---|---|---|---|
| 7c49a84 | 2026-09-22 04:12 +0300 | BuildInfo паспорт tenzor-module-build-v1, ранний --version-json | src/main.rs |
| 9ff28cf | 2026-09-22 22:36 +0300 | Паспорт модуля: fingerprint lock, metadata defaults | src/main.rs |
| db35b41 | 2026-09-23 15:42 +0300 | Исправление паспорта сборки | src/main.rs |

Суммарно от 8472fd2 изменён только `src/main.rs`.

## CI/CD
`.github/workflows/ci.yml`: триггеры `push`, `pull_request`; шаги fmt, test, clippy, netns-тест egress guard (sudo, Linux). Автоматических deploy/schedule/release нет. Результаты CI на GitHub не запрашивались (доступ не проверялся).

## Локальные проверки на db35b41 (без prod, чистое дерево)
| Команда | Код |
|---|---|
| `cargo fmt --check` | 0 |
| `cargo clippy --all-targets --locked -- -D warnings` | 0 |
| `cargo test --locked` (CARGO_TARGET_DIR отдельный) | 0, 14 passed |
| `TENZOR_WEBAPP_RELAY_TEST_BINARY=… ./tests/test-packaging.sh` | 0, «packaging and config validation: ok» |
Первая попытка `cargo test` в общем target-каталоге упала с ошибкой записи .o (внешний сбой среды, не кода); повтор в отдельном каталоге прошёл. netns-тест не запускался (Linux/root; macOS).

## Зависимости контрактов
Изменён только формат паспорта `--version-json` (tenzor-module-build-v1, поля добавлены, существующие сохранены). Потребители — сборочные/паспортные проверки в других модулях (tenzor-server/tenzor-client не импортируют код relay; протокол CONNECT и подписанный scope в PROTOCOL.md не менялись). Интеграционным карточкам файлы этого репозитория не нужны, кроме проверки `--version-json` на стороне потребителя паспорта; изменений протокола нет (доказано diff: только src/main.rs).
