# Вход от имени компании через Taler ID — план 2: мобильное приложение

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Нативный экран согласия «Вход через Taler ID» показывает выбор «Войти как» и «Передать данные компаний», отправляет его в `/oauth/mobile/approve`; сломанная кнопка «Открыть в браузере» убрана.

**Architecture:** `GrantInfo` получает необязательный блок `companies` (как его отдаёт бэкенд из плана 1). Выбор хранится в состоянии BLoC (`CompanySelection`), меняется событиями и уходит в `approve` вместе с параметрами запроса.

**Tech Stack:** Flutter 3.38, flutter_bloc + bloc_test, freezed 2.5 / json_serializable, mocktail.

**Спека:** `~/taler-id/docs/superpowers/specs/2026-11-19-companies-oauth-design.md`, часть 3. **Зависимость:** план 1 (задача 14) — ручки `grant-info` с блоком `companies` и `approve` с `act_as` / `company_ids`.

---

## Карта файлов (репозиторий `~/Downloads/taler_id_mobile`, ветка `feat/companies-consent` от `origin/dev`)

**Создаются:**
- `lib/features/oauth/domain/entities/company_consent.dart` — блок компаний из `grant-info` и выбор человека.
- `test/features/oauth/company_consent_test.dart`.

**Меняются:**
- `lib/features/oauth/domain/entities/grant_info.dart` (+ перегенерация `grant_info.freezed.dart`, `grant_info.g.dart`).
- `lib/features/oauth/domain/repositories/oauth_repository.dart`, `lib/features/oauth/data/repositories/oauth_repository_impl.dart`, `lib/features/oauth/data/datasources/oauth_remote_datasource.dart` — выбор в `approve`.
- `lib/features/oauth/presentation/bloc/oauth_authorize_{event,state,bloc}.dart` — выбор в состоянии.
- `lib/features/oauth/presentation/screens/oauth_authorize_screen.dart` — блоки выбора, без кнопки «Открыть в браузере».
- `test/features/oauth/oauth_authorize_bloc_test.dart`, `test/features/oauth/oauth_authorize_screen_test.dart`.

Тексты экрана — по-русски прямо в коде, как весь этот экран сейчас.

---

### Task 0: Подготовка

- [ ] **Step 1: Ветка**

```bash
cd ~/Downloads/taler_id_mobile && git fetch -q origin
git worktree add -q -b feat/companies-consent .worktrees/companies-consent origin/dev
cd .worktrees/companies-consent && flutter pub get >/dev/null && git log --oneline -1
```

- [ ] **Step 2: База**

```bash
flutter test --no-pub test/features/oauth 2>&1 | tail -1
```
Expected: `All tests passed!`.

---

### Task 1: Блок компаний и выбор

**Files:**
- Create: `lib/features/oauth/domain/entities/company_consent.dart`
- Test: `test/features/oauth/company_consent_test.dart`

- [ ] **Step 1: Failing test**

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/oauth/domain/entities/company_consent.dart';

const _json = {
  'person': {'name': 'Иван Петров'},
  'eligible': [
    {'id': 'a', 'name': 'Ромашка', 'legal_name': 'ООО «Ромашка»', 'logo_url': null, 'role': 'OWNER'},
    {'id': 'b', 'name': 'Лютик', 'legal_name': null, 'logo_url': null, 'role': 'ADMIN'},
  ],
  'unverified': [
    {'id': 'c', 'name': 'Василёк'},
  ],
  'last_selection': {'act_as': 'a', 'company_ids': ['a']},
};

void main() {
  group('CompanyConsent.fromJson', () {
    test('reads the block grant-info sends', () {
      final c = CompanyConsent.fromJson(_json);
      expect(c.personName, 'Иван Петров');
      expect(c.eligible.map((e) => e.displayName), ['ООО «Ромашка»', 'Лютик']);
      expect(c.unverified.single.name, 'Василёк');
      expect(c.lastSelection, const CompanySelection(actAs: 'a', companyIds: ['a']));
    });

    test('round-trips through toJson without jsonEncode', () {
      final c = CompanyConsent.fromJson(_json);
      expect(CompanyConsent.fromJson(c.toJson()), c);
    });

    test('null stays null', () {
      expect(CompanyConsent.fromJsonOrNull(null), isNull);
    });
  });

  group('CompanySelection', () {
    test('defaults: last choice if any, otherwise a person sharing nothing', () {
      final c = CompanyConsent.fromJson(_json);
      expect(CompanySelection.initialFor(c), const CompanySelection(actAs: 'a', companyIds: ['a']));
      final noLast = CompanyConsent.fromJson({..._json, 'last_selection': null});
      expect(CompanySelection.initialFor(noLast), const CompanySelection(actAs: 'person', companyIds: []));
    });

    test('acting as a company always shares it', () {
      const s = CompanySelection(actAs: 'person', companyIds: []);
      expect(s.withActAs('b'), const CompanySelection(actAs: 'b', companyIds: ['b']));
    });

    test('the act-as company cannot be unshared, others toggle', () {
      const s = CompanySelection(actAs: 'a', companyIds: ['a']);
      expect(s.toggled('a', false), s);
      expect(s.toggled('b', true), const CompanySelection(actAs: 'a', companyIds: ['a', 'b']));
      expect(s.toggled('b', true).toggled('b', false), s);
    });

    test('approve body', () {
      expect(const CompanySelection(actAs: 'a', companyIds: ['a', 'b']).toApproveFields(),
          {'act_as': 'a', 'company_ids': ['a', 'b']});
    });
  });
}
```

- [ ] **Step 2: Run, expect FAIL**

Run: `flutter test --no-pub test/features/oauth/company_consent_test.dart`
Expected: FAIL — файл `company_consent.dart` не найден.

- [ ] **Step 3: Implementation**

```dart
import 'package:equatable/equatable.dart';

/// Блок «компании» из /oauth/mobile/grant-info (scope `companies`).
///
/// Обычные классы, а не freezed: вложенная freezed-сущность в freezed-модели
/// требует explicitToJson и легко ломает fromJson(toJson()) — здесь (де)сериализация
/// явная. Спека taler-id: docs/superpowers/specs/2026-11-19-companies-oauth-design.md
class CompanyConsent extends Equatable {
  final String personName;
  final List<CompanyOption> eligible;
  final List<UnverifiedCompany> unverified;
  final CompanySelection? lastSelection;

  const CompanyConsent({
    required this.personName,
    required this.eligible,
    required this.unverified,
    this.lastSelection,
  });

  factory CompanyConsent.fromJson(Map<String, dynamic> json) {
    final last = json['last_selection'] as Map<String, dynamic>?;
    return CompanyConsent(
      personName: ((json['person'] as Map<String, dynamic>?)?['name'] as String?) ?? '',
      eligible: ((json['eligible'] as List?) ?? const [])
          .map((e) => CompanyOption.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList(),
      unverified: ((json['unverified'] as List?) ?? const [])
          .map((e) => UnverifiedCompany.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList(),
      lastSelection: last == null
          ? null
          : CompanySelection(
              actAs: last['act_as'] as String? ?? CompanySelection.person,
              companyIds: List<String>.from(last['company_ids'] as List? ?? const []),
            ),
    );
  }

  static CompanyConsent? fromJsonOrNull(Object? json) =>
      json == null ? null : CompanyConsent.fromJson(Map<String, dynamic>.from(json as Map));

  static Map<String, dynamic>? toJsonOrNull(CompanyConsent? c) => c?.toJson();

  Map<String, dynamic> toJson() => {
        'person': {'name': personName},
        'eligible': eligible.map((e) => e.toJson()).toList(),
        'unverified': unverified.map((e) => e.toJson()).toList(),
        'last_selection': lastSelection?.toApproveFields(),
      };

  @override
  List<Object?> get props => [personName, eligible, unverified, lastSelection];
}

class CompanyOption extends Equatable {
  final String id;
  final String name;
  final String? legalName;
  final String? logoUrl;
  final String role;

  const CompanyOption({
    required this.id,
    required this.name,
    this.legalName,
    this.logoUrl,
    required this.role,
  });

  /// Проверенное юридическое название, если есть, иначе название в Taler ID.
  String get displayName => legalName ?? name;

  factory CompanyOption.fromJson(Map<String, dynamic> json) => CompanyOption(
        id: json['id'] as String,
        name: json['name'] as String? ?? '',
        legalName: json['legal_name'] as String?,
        logoUrl: json['logo_url'] as String?,
        role: json['role'] as String? ?? '',
      );

  Map<String, dynamic> toJson() =>
      {'id': id, 'name': name, 'legal_name': legalName, 'logo_url': logoUrl, 'role': role};

  @override
  List<Object?> get props => [id, name, legalName, logoUrl, role];
}

class UnverifiedCompany extends Equatable {
  final String id;
  final String name;

  const UnverifiedCompany({required this.id, required this.name});

  factory UnverifiedCompany.fromJson(Map<String, dynamic> json) =>
      UnverifiedCompany(id: json['id'] as String, name: json['name'] as String? ?? '');

  Map<String, dynamic> toJson() => {'id': id, 'name': name};

  @override
  List<Object?> get props => [id, name];
}

/// «Войти как» и «какие компании передать». Компания из «войти как»
/// передаётся всегда — снять её галочку нельзя (сервер проверяет то же).
class CompanySelection extends Equatable {
  static const person = 'person';

  final String actAs;
  final List<String> companyIds;

  const CompanySelection({required this.actAs, required this.companyIds});

  factory CompanySelection.initialFor(CompanyConsent c) =>
      c.lastSelection ?? const CompanySelection(actAs: person, companyIds: []);

  CompanySelection withActAs(String id) => CompanySelection(
        actAs: id,
        companyIds: id == person || companyIds.contains(id) ? companyIds : [...companyIds, id],
      );

  CompanySelection toggled(String id, bool on) {
    if (id == actAs) return this;
    final rest = companyIds.where((x) => x != id).toList();
    return CompanySelection(actAs: actAs, companyIds: on ? [...rest, id] : rest);
  }

  Map<String, dynamic> toApproveFields() => {'act_as': actAs, 'company_ids': companyIds};

  @override
  List<Object?> get props => [actAs, companyIds];
}
```

- [ ] **Step 4: Run, expect PASS**

Run: `flutter test --no-pub test/features/oauth/company_consent_test.dart`
Expected: `All tests passed!` (8 тестов).

- [ ] **Step 5: Commit**

```bash
git add lib/features/oauth/domain/entities/company_consent.dart test/features/oauth/company_consent_test.dart
git commit -qm "feat(oauth): блок компаний из grant-info и выбор человека

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `GrantInfo.companies`

**Files:**
- Modify: `lib/features/oauth/domain/entities/grant_info.dart` (+ генерация)
- Test: `test/features/oauth/company_consent_test.dart` (новая группа)

- [ ] **Step 1: Failing test** — в конец `main()` в `company_consent_test.dart` (импорт `grant_info.dart`):

```dart
  group('GrantInfo.companies', () {
    test('parsed when grant-info sends it', () {
      final g = GrantInfo.fromJson({
        'client_name': 'Trientes',
        'scopes': [],
        'remembered': false,
        'companies': _json,
      });
      expect(g.companies?.eligible.length, 2);
    });

    test('absent → null, older backends unaffected', () {
      final g = GrantInfo.fromJson({'client_name': 'MyBook', 'scopes': [], 'remembered': true});
      expect(g.companies, isNull);
    });

    test('round-trips without jsonEncode', () {
      final g = GrantInfo.fromJson({'client_name': 'T', 'scopes': [], 'remembered': false, 'companies': _json});
      expect(GrantInfo.fromJson(g.toJson()), g);
    });
  });
```

- [ ] **Step 2: Run, expect FAIL**

Run: `flutter test --no-pub test/features/oauth/company_consent_test.dart`
Expected: FAIL — у `GrantInfo` нет `companies`.

- [ ] **Step 3: Implementation**

`grant_info.dart`:

```dart
// ignore_for_file: invalid_annotation_target
import 'package:freezed_annotation/freezed_annotation.dart';
import 'company_consent.dart';
import 'scope_descriptor.dart';

part 'grant_info.freezed.dart';
part 'grant_info.g.dart';

@freezed
class GrantInfo with _$GrantInfo {
  const factory GrantInfo({
    @JsonKey(name: 'client_name') required String clientName,
    @JsonKey(name: 'client_logo') String? clientLogo,
    required List<ScopeDescriptor> scopes,
    required bool remembered,
    // Блок scope `companies`; (де)сериализация явная — см. company_consent.dart.
    @JsonKey(fromJson: CompanyConsent.fromJsonOrNull, toJson: CompanyConsent.toJsonOrNull)
    CompanyConsent? companies,
  }) = _GrantInfo;

  factory GrantInfo.fromJson(Map<String, dynamic> json) =>
      _$GrantInfoFromJson(json);
}
```

Перегенерировать только файлы `GrantInfo`:

```bash
dart run build_runner build --delete-conflicting-outputs --build-filter="lib/features/oauth/domain/entities/grant_info.*.dart"
git status --short lib/
```
Expected: изменились только `grant_info.dart`, `grant_info.freezed.dart`, `grant_info.g.dart`. Если `--build-filter` не поддерживается версией build_runner — запустить без него и откатить (`git checkout -- <файл>`) все прочие изменённые `*.g.dart` / `*.freezed.dart`.

Прочитать `grant_info.g.dart`: в `_$$GrantInfoImplToJson` должно быть `'companies': CompanyConsent.toJsonOrNull(instance.companies)`.

- [ ] **Step 4: Run, expect PASS**

Run: `flutter test --no-pub test/features/oauth`
Expected: `All tests passed!`.

- [ ] **Step 5: Commit**

```bash
git add lib/features/oauth/domain/entities/grant_info.dart lib/features/oauth/domain/entities/grant_info.freezed.dart lib/features/oauth/domain/entities/grant_info.g.dart test/features/oauth/company_consent_test.dart
git commit -qm "feat(oauth): GrantInfo.companies — блок выбора компаний

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Выбор уходит в approve

**Files:**
- Modify: `lib/features/oauth/domain/repositories/oauth_repository.dart`, `lib/features/oauth/data/repositories/oauth_repository_impl.dart`, `lib/features/oauth/data/datasources/oauth_remote_datasource.dart`

- [ ] **Step 1: Implementation** (поведение проверяется тестами BLoC в задаче 4)

`oauth_repository.dart`:

```dart
import '../entities/company_consent.dart';
import '../entities/grant_info.dart';
import '../entities/oauth_authorize_params.dart';

class OAuthApproveResult {
  final String redirectUri;
  const OAuthApproveResult(this.redirectUri);
}

abstract class OAuthRepository {
  Future<GrantInfo> getGrantInfo(OAuthAuthorizeParams params);
  Future<OAuthApproveResult> approve(OAuthAuthorizeParams params, {CompanySelection? selection});
}
```

`oauth_repository_impl.dart`:

```dart
  @override
  Future<OAuthApproveResult> approve(OAuthAuthorizeParams params, {CompanySelection? selection}) async {
    final redirectUri = await _remote.approve(params, selection: selection);
    return OAuthApproveResult(redirectUri);
  }
```
(импорт `../../domain/entities/company_consent.dart`).

`oauth_remote_datasource.dart`:

```dart
  Future<String> approve(OAuthAuthorizeParams params, {CompanySelection? selection}) => client.post(
        '/oauth/mobile/approve',
        data: {
          ...params.toQueryParameters(),
          if (selection != null) ...selection.toApproveFields(),
        },
        fromJson: (d) => Map<String, dynamic>.from(d)['redirect_uri'] as String,
      );
```
(импорт `../../domain/entities/company_consent.dart`).

- [ ] **Step 2: Analyze**

Run: `flutter analyze lib/features/oauth`
Expected: ошибки только в тестах/моках, которые вызывают `approve(params)` с одной позиционной — их нет, параметр именованный; `No issues found!` либо только старые замечания этих файлов.

- [ ] **Step 3: Commit**

```bash
git add lib/features/oauth/domain/repositories/oauth_repository.dart lib/features/oauth/data
git commit -qm "feat(oauth): выбор компаний уходит в /oauth/mobile/approve

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: BLoC — выбор в состоянии

**Files:**
- Modify: `lib/features/oauth/presentation/bloc/oauth_authorize_event.dart`, `oauth_authorize_state.dart`, `oauth_authorize_bloc.dart`
- Test: `test/features/oauth/oauth_authorize_bloc_test.dart`

- [ ] **Step 1: Failing tests** — в `oauth_authorize_bloc_test.dart`:

Вверху (импорт `company_consent.dart`):

```dart
const _companies = CompanyConsent(
  personName: 'Иван',
  eligible: [
    CompanyOption(id: 'a', name: 'Ромашка', legalName: 'ООО «Ромашка»', role: 'OWNER'),
    CompanyOption(id: 'b', name: 'Лютик', role: 'ADMIN'),
  ],
  unverified: [],
  lastSelection: CompanySelection(actAs: 'a', companyIds: ['a']),
);

const _grantInfoCompanies = GrantInfo(
  clientName: 'Trientes',
  scopes: [ScopeDescriptor(key: 'companies', label: 'Компании', description: '...')],
  remembered: false,
  companies: _companies,
);
```
в `setUpAll` — `registerFallbackValue(const CompanySelection(actAs: 'person', companyIds: []));`. Все существующие `when(() => repo.approve(any()))` заменить на `when(() => repo.approve(any(), selection: any(named: 'selection')))`.

Новые тесты в `group('OAuthAuthorizeBloc')`:

```dart
    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'with companies the selection starts from the last choice',
      build: () {
        final repo = _MockRepo();
        when(() => repo.getGrantInfo(any())).thenAnswer((_) async => _grantInfoCompanies);
        return OAuthAuthorizeBloc(repo);
      },
      act: (bloc) => bloc.add(const LoadGrantInfo(_params)),
      expect: () => [
        const OAuthLoading(),
        const OAuthConsentRequired(_grantInfoCompanies, _params,
            selection: CompanySelection(actAs: 'a', companyIds: ['a'])),
      ],
    );

    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'ActAsChanged switches who signs in and shares that company',
      build: () => OAuthAuthorizeBloc(_MockRepo()),
      seed: () => const OAuthConsentRequired(_grantInfoCompanies, _params,
          selection: CompanySelection(actAs: 'person', companyIds: [])),
      act: (bloc) => bloc.add(const ActAsChanged('b')),
      expect: () => [
        const OAuthConsentRequired(_grantInfoCompanies, _params,
            selection: CompanySelection(actAs: 'b', companyIds: ['b'])),
      ],
    );

    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'ShareToggled adds and removes a company',
      build: () => OAuthAuthorizeBloc(_MockRepo()),
      seed: () => const OAuthConsentRequired(_grantInfoCompanies, _params,
          selection: CompanySelection(actAs: 'a', companyIds: ['a'])),
      act: (bloc) => bloc
        ..add(const ShareToggled('b', true))
        ..add(const ShareToggled('a', false)),
      expect: () => [
        const OAuthConsentRequired(_grantInfoCompanies, _params,
            selection: CompanySelection(actAs: 'a', companyIds: ['a', 'b'])),
      ],
    );

    late _MockRepo approveRepo;
    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'Approve sends the selection',
      build: () {
        approveRepo = _MockRepo();
        when(() => approveRepo.approve(any(), selection: any(named: 'selection')))
            .thenAnswer((_) async => const OAuthApproveResult('https://trientes.org/cb?code=x'));
        return OAuthAuthorizeBloc(approveRepo);
      },
      seed: () => const OAuthConsentRequired(_grantInfoCompanies, _params,
          selection: CompanySelection(actAs: 'b', companyIds: ['b'])),
      act: (bloc) => bloc.add(const ApprovePressed()),
      expect: () => [
        const OAuthApproving(_grantInfoCompanies, _params,
            selection: CompanySelection(actAs: 'b', companyIds: ['b'])),
        const OAuthSuccess('https://trientes.org/cb?code=x'),
      ],
      verify: (_) => verify(() => approveRepo.approve(_params,
          selection: const CompanySelection(actAs: 'b', companyIds: ['b']))).called(1),
    );
```

- [ ] **Step 2: Run, expect FAIL**

Run: `flutter test --no-pub test/features/oauth/oauth_authorize_bloc_test.dart`
Expected: FAIL — нет `selection`, `ActAsChanged`, `ShareToggled`.

- [ ] **Step 3: Implementation**

`oauth_authorize_event.dart` — в конец:

```dart
class ActAsChanged extends OAuthAuthorizeEvent {
  /// 'person' или id компании.
  final String actAs;
  const ActAsChanged(this.actAs);
  @override
  List<Object?> get props => [actAs];
}

class ShareToggled extends OAuthAuthorizeEvent {
  final String companyId;
  final bool on;
  const ShareToggled(this.companyId, this.on);
  @override
  List<Object?> get props => [companyId, on];
}
```

`oauth_authorize_state.dart` — `OAuthConsentRequired` и `OAuthApproving` (импорт `company_consent.dart`):

```dart
class OAuthConsentRequired extends OAuthAuthorizeState {
  final GrantInfo grantInfo;
  final OAuthAuthorizeParams params;
  /// Есть, только если сайт просит `companies` и есть подходящая компания.
  final CompanySelection? selection;
  const OAuthConsentRequired(this.grantInfo, this.params, {this.selection});
  @override
  List<Object?> get props => [grantInfo, params, selection];
}

class OAuthApproving extends OAuthAuthorizeState {
  final GrantInfo grantInfo;
  final OAuthAuthorizeParams params;
  final CompanySelection? selection;
  const OAuthApproving(this.grantInfo, this.params, {this.selection});
  @override
  List<Object?> get props => [grantInfo, params, selection];
}
```

`oauth_authorize_bloc.dart`:
- поле `CompanySelection? _currentSelection;`, регистрация `on<ActAsChanged>(_onActAs); on<ShareToggled>(_onShare);`
- в `_onLoad`, ветка `else`:

```dart
        final companies = grantInfo.companies;
        _currentSelection = companies != null && companies.eligible.isNotEmpty
            ? CompanySelection.initialFor(companies)
            : null;
        emit(OAuthConsentRequired(grantInfo, event.params, selection: _currentSelection));
```
- в `_onApprove`: при чтении из `OAuthConsentRequired` брать и `s.selection` в локальную `selection` (иначе `_currentSelection`); `emit(OAuthApproving(grantInfo, params, selection: selection));`, `await _repo.approve(params, selection: selection);`, в `catch` — `emit(OAuthConsentRequired(grantInfo, params, selection: selection));`.
- автоодобрение (`remembered`) — `await _repo.approve(event.params);` без выбора (бэкенд ставит `remembered=false`, когда выбор нужен).
- новые обработчики:

```dart
  void _onActAs(ActAsChanged event, Emitter<OAuthAuthorizeState> emit) {
    final s = state;
    if (s is! OAuthConsentRequired || s.selection == null) return;
    _currentSelection = s.selection!.withActAs(event.actAs);
    emit(OAuthConsentRequired(s.grantInfo, s.params, selection: _currentSelection));
  }

  void _onShare(ShareToggled event, Emitter<OAuthAuthorizeState> emit) {
    final s = state;
    if (s is! OAuthConsentRequired || s.selection == null) return;
    final next = s.selection!.toggled(event.companyId, event.on);
    if (next == s.selection) return;
    _currentSelection = next;
    emit(OAuthConsentRequired(s.grantInfo, s.params, selection: next));
  }
```

- [ ] **Step 4: Run, expect PASS**

Run: `flutter test --no-pub test/features/oauth`
Expected: `All tests passed!`.

- [ ] **Step 5: Commit**

```bash
git add lib/features/oauth/presentation/bloc test/features/oauth/oauth_authorize_bloc_test.dart
git commit -qm "feat(oauth): выбор «войти как» и «передать компании» в состоянии BLoC

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Экран — блоки выбора, без «Открыть в браузере»

**Files:**
- Modify: `lib/features/oauth/presentation/screens/oauth_authorize_screen.dart`
- Test: `test/features/oauth/oauth_authorize_screen_test.dart`

- [ ] **Step 1: Failing tests** — в `oauth_authorize_screen_test.dart` (импорт `company_consent.dart`):

```dart
const _companies = CompanyConsent(
  personName: 'Иван Петров',
  eligible: [CompanyOption(id: 'a', name: 'Ромашка', legalName: 'ООО «Ромашка»', role: 'OWNER')],
  unverified: [UnverifiedCompany(id: 'c', name: 'Василёк')],
);
const _grantInfoCompanies = GrantInfo(
  clientName: 'Trientes', scopes: [], remembered: false, companies: _companies,
);

  testWidgets('companies: act-as choices, share list, unverified hint', (tester) async {
    final bloc = _MockBloc();
    when(() => bloc.state).thenReturn(const OAuthConsentRequired(_grantInfoCompanies, _params,
        selection: CompanySelection(actAs: 'a', companyIds: ['a'])));
    when(() => bloc.stream).thenAnswer((_) => const Stream.empty());

    await tester.pumpWidget(_harness(bloc));
    await tester.pumpAndSettle();

    expect(find.text('Войти как'), findsOneWidget);
    expect(find.text('Иван Петров'), findsOneWidget);
    expect(find.text('ООО «Ромашка»'), findsNWidgets(2)); // «войти как» и «передать»
    expect(find.text('Передать данные компаний'), findsOneWidget);
    expect(find.textContaining('Василёк'), findsOneWidget);
    // компания из «войти как» отмечена и заблокирована
    final box = tester.widget<CheckboxListTile>(find.byType(CheckboxListTile));
    expect(box.value, isTrue);
    expect(box.onChanged, isNull);
  });

  testWidgets('tapping a person option dispatches ActAsChanged', (tester) async {
    final bloc = _MockBloc();
    when(() => bloc.state).thenReturn(const OAuthConsentRequired(_grantInfoCompanies, _params,
        selection: CompanySelection(actAs: 'a', companyIds: ['a'])));
    when(() => bloc.stream).thenAnswer((_) => const Stream.empty());

    await tester.pumpWidget(_harness(bloc));
    await tester.tap(find.text('Иван Петров'));
    await tester.pump();

    verify(() => bloc.add(const ActAsChanged('person'))).called(1);
  });

  testWidgets('failure screen has no broken "open in browser" link', (tester) async {
    final bloc = _MockBloc();
    when(() => bloc.state).thenReturn(const OAuthFailure('boom', _params));
    when(() => bloc.stream).thenAnswer((_) => const Stream.empty());

    await tester.pumpWidget(_harness(bloc));
    await tester.pumpAndSettle();

    expect(find.text('Повторить'), findsOneWidget);
    expect(find.text('Открыть в браузере'), findsNothing);
  });
```
Если в файле уже есть тест на кнопку «Открыть в браузере» — удалить его.

- [ ] **Step 2: Run, expect FAIL**

Run: `flutter test --no-pub test/features/oauth/oauth_authorize_screen_test.dart`
Expected: FAIL — нет блоков выбора, кнопка «Открыть в браузере» на месте.

- [ ] **Step 3: Implementation**

- `build`: в ветках `OAuthApproving` и `OAuthConsentRequired` передавать выбор:
```dart
          if (state is OAuthApproving) {
            return _buildConsent(context, state.grantInfo, state.selection, busy: true);
          }
          if (state is OAuthConsentRequired) {
            return _buildConsent(context, state.grantInfo, state.selection, busy: false);
          }
```
- `_buildConsent(BuildContext context, GrantInfo grantInfo, CompanySelection? selection, {required bool busy})`: обернуть содержимое в `ListView` вместо `Column` + `Spacer` (блоки выбора не влезают в экран), а после списка scopes вставить:

```dart
          if (selection != null && grantInfo.companies != null)
            ..._buildCompanies(context, grantInfo.companies!, selection, busy: busy),
```
- новый метод:

```dart
  // Выбор «войти как» и «что передать» (scope companies). Компания из
  // «войти как» передаётся всегда — её галочка отмечена и заблокирована.
  List<Widget> _buildCompanies(
    BuildContext context,
    CompanyConsent companies,
    CompanySelection selection, {
    required bool busy,
  }) {
    final bloc = context.read<OAuthAuthorizeBloc>();
    final title = Theme.of(context).textTheme.titleMedium;
    return [
      const SizedBox(height: 16),
      Text('Войти как', style: title),
      RadioListTile<String>(
        value: CompanySelection.person,
        groupValue: selection.actAs,
        title: Text(companies.personName.isEmpty ? 'Вы' : companies.personName),
        subtitle: const Text('Физлицо'),
        contentPadding: EdgeInsets.zero,
        onChanged: busy ? null : (v) => bloc.add(ActAsChanged(v!)),
      ),
      ...companies.eligible.map((c) => RadioListTile<String>(
            value: c.id,
            groupValue: selection.actAs,
            title: Text(c.displayName),
            subtitle: const Text('KYB пройден'),
            contentPadding: EdgeInsets.zero,
            onChanged: busy ? null : (v) => bloc.add(ActAsChanged(v!)),
          )),
      const SizedBox(height: 16),
      Text('Передать данные компаний', style: title),
      ...companies.eligible.map((c) {
        final locked = selection.actAs == c.id;
        return CheckboxListTile(
          value: locked || selection.companyIds.contains(c.id),
          title: Text(c.displayName),
          contentPadding: EdgeInsets.zero,
          controlAffinity: ListTileControlAffinity.leading,
          onChanged: busy || locked ? null : (v) => bloc.add(ShareToggled(c.id, v ?? false)),
        );
      }),
      if (companies.unverified.isNotEmpty)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(
            'Не прошли KYB: ${companies.unverified.map((c) => c.name).join(', ')}. '
            'Пройдите проверку компании в разделе «Организации» — тогда её можно будет выбрать.',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ),
    ];
  }
```
(импорт `../../domain/entities/company_consent.dart`).

- `_buildFailure`: удалить переменную `fallback` и `TextButton` «Открыть в браузере» вместе с `SizedBox` перед ним; над кнопкой «Повторить» комментарий:

```dart
          // «Открыть в браузере» вела на /oauth/authorize, которого нет, а
          // правильный /oauth/auth приложение перехватило бы снова (App Links).
```
Если после этого `AppConfig` в файле больше не используется — убрать его импорт.

- [ ] **Step 4: Run, expect PASS**

Run: `flutter test --no-pub test/features/oauth && flutter analyze lib/features/oauth test/features/oauth`
Expected: `All tests passed!`; новых замечаний анализатора нет.

- [ ] **Step 5: Commit**

```bash
git add lib/features/oauth/presentation/screens/oauth_authorize_screen.dart test/features/oauth/oauth_authorize_screen_test.dart
git commit -qm "feat(oauth): экран согласия — «войти как» и «передать данные компаний»

Убрана кнопка «Открыть в браузере»: она вела на несуществующий
/oauth/authorize, а /oauth/auth приложение перехватило бы снова.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Полный прогон и ветка

- [ ] **Step 1: Все тесты**

```bash
flutter test --no-pub 2>&1 | tail -1
```
Expected: `All tests passed!` (плавающий `messenger_bloc_test … CallInviteReceived` при падении перезапустить — он не связан с этой работой).

- [ ] **Step 2: Вживую** — после выкатки плана 1 на DEV: dev-сборка на эмуляторе (см. память «Эмулятор на маке: DEV недоступен по TLS» — собирать с `--dart-define=BASE_URL=https://id.taler.tirol`, если план 1 уже на TEST), войти `integration_test`, открыть в браузере эмулятора ссылку `/oauth/auth?client_id=companies-e2e&…&scope=openid%20profile%20companies…` — её перехватит приложение — увидеть оба блока, выбрать компанию, «Разрешить» → браузер уходит на `http://localhost:19999/cb?code=…`. В журнале бэкенда — `OAUTH_COMPANIES_SHARED`.

- [ ] **Step 3: В `dev`**

```bash
git fetch -q origin && git rebase -q origin/dev && git push -q origin HEAD:dev
```
Релиз мобилки — отдельным решением (bump версии, `APP_RELEASES`, сборки — по CLAUDE.md).
