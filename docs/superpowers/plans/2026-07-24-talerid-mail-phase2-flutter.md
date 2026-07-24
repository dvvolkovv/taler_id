# Taler ID Mail — Phase 2 (Flutter UI + assistant tools) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Пользователь видит почту в приложении: выбор адреса после онбординга, раздел «Почта» (inbox/чтение/compose/reply/вложения), управление app-паролями в Настройках, и всё это доступно голосом через ассистента (check_mail/read_mail/send_mail/create_mail_app_password).

**Architecture:** Новая фича `lib/features/mail/` по Clean Architecture-паттерну репо (datasource → repository → BLoC → screens), REST на готовый Phase 1 API `/mail/*`. Шаг выбора адреса встраивается в `post_login_redirect.dart` (гейт после онбординга). Assistant-tools добавляются на клиенте (schema + executor) + инструкции в backend-промптах + зеркальные MCP-tools на бэкенде.

**Tech Stack:** Flutter (BLoC, GoRouter, GetIt, DioClient, webview_flutter, file_picker, open_filex), bloc_test+mocktail; backend: prompts ru/en.md, src/mcp/tools (zod).

**Spec:** `taler_id/docs/superpowers/specs/2026-07-24-talerid-mail-hosting-design.md`. Phase 1 (backend API) готов и задеплоен на DEV.

**Репозитории:**
- Mobile: `~/Downloads/taler_id_mobile/.worktrees/dev-merge` (ветка `dev` — работать здесь!)
- Backend: `~/Downloads/taler_id` (ветка `dev`)

**Phase 1 API (контракт, зафиксирован):**
- `GET /mail/availability?localpart=x` → `{localpart, available, reason?}` (reason: INVALID|RESERVED|TAKEN)
- `POST /mail/account {localpart}` → аккаунт; `GET /mail/account` → `{address, localpart, domain, status, quotaBytes, clientSettings:{host, imapPort, imapSecurity, smtpPort, smtpSecurity, login}}`; 404 если ящика нет
- `POST /mail/app-passwords {label}` → `{id, label, password, clientSettings}` (password показывается один раз); `GET /mail/app-passwords` → `[{id,label,createdAt}]`; `DELETE /mail/app-passwords/:id`
- `GET /mail/messages?folder=INBOX&beforeUid=N` → `{items:[{uid,from,fromAddress,subject,date,seen,snippet,hasAttachments}], nextCursor}`
- `GET /mail/messages/:uid` → `{uid,from,to,subject,date,messageId,html,text,attachments:[{index,filename,contentType,size}]}`
- `GET /mail/messages/:uid/attachments/:index` → бинарный стрим
- `POST /mail/messages {to,subject,text,inReplyTo?,attachments?:[{filename,contentBase64}]}` → `{ok:true}`
- `POST /mail/messages/:uid/read|unread`, `DELETE /mail/messages/:uid`

---

### Task 1: Entities + RemoteDataSource + Repository (Flutter)

**Files:**
- Create: `lib/features/mail/domain/entities/mail_entities.dart`
- Create: `lib/features/mail/data/datasources/mail_remote_datasource.dart`
- Create: `lib/features/mail/domain/repositories/i_mail_repository.dart`
- Create: `lib/features/mail/data/repositories/mail_repository_impl.dart`

Entities — простые классы без Freezed (паттерн `features/contacts`), чтобы не плодить codegen.

- [x] **Step 1: `mail_entities.dart`**

```dart
class MailAccountEntity {
  final String address;
  final String localpart;
  final String domain;
  final String status; // PROVISIONING | ACTIVE | SUSPENDED
  final MailClientSettings? clientSettings;

  MailAccountEntity({
    required this.address,
    required this.localpart,
    required this.domain,
    required this.status,
    this.clientSettings,
  });

  factory MailAccountEntity.fromJson(Map<String, dynamic> json) =>
      MailAccountEntity(
        address: json['address'] as String,
        localpart: json['localpart'] as String,
        domain: json['domain'] as String,
        status: json['status'] as String,
        clientSettings: json['clientSettings'] != null
            ? MailClientSettings.fromJson(
                Map<String, dynamic>.from(json['clientSettings'] as Map))
            : null,
      );
}

class MailClientSettings {
  final String host;
  final int imapPort;
  final int smtpPort;
  final String login;

  MailClientSettings({
    required this.host,
    required this.imapPort,
    required this.smtpPort,
    required this.login,
  });

  factory MailClientSettings.fromJson(Map<String, dynamic> json) =>
      MailClientSettings(
        host: json['host'] as String,
        imapPort: (json['imapPort'] as num).toInt(),
        smtpPort: (json['smtpPort'] as num).toInt(),
        login: json['login'] as String,
      );
}

class MailListItemEntity {
  final int uid;
  final String from;
  final String fromAddress;
  final String subject;
  final DateTime date;
  final bool seen;
  final String snippet;
  final bool hasAttachments;

  MailListItemEntity({
    required this.uid,
    required this.from,
    required this.fromAddress,
    required this.subject,
    required this.date,
    required this.seen,
    required this.snippet,
    required this.hasAttachments,
  });

  factory MailListItemEntity.fromJson(Map<String, dynamic> json) =>
      MailListItemEntity(
        uid: (json['uid'] as num).toInt(),
        from: json['from'] as String? ?? '',
        fromAddress: json['fromAddress'] as String? ?? '',
        subject: json['subject'] as String? ?? '',
        date: DateTime.tryParse(json['date'] as String? ?? '') ?? DateTime.now(),
        seen: json['seen'] as bool? ?? false,
        snippet: json['snippet'] as String? ?? '',
        hasAttachments: json['hasAttachments'] as bool? ?? false,
      );

  MailListItemEntity copyWith({bool? seen}) => MailListItemEntity(
        uid: uid,
        from: from,
        fromAddress: fromAddress,
        subject: subject,
        date: date,
        seen: seen ?? this.seen,
        snippet: snippet,
        hasAttachments: hasAttachments,
      );
}

class MailAttachmentEntity {
  final int index;
  final String filename;
  final String contentType;
  final int size;

  MailAttachmentEntity({
    required this.index,
    required this.filename,
    required this.contentType,
    required this.size,
  });

  factory MailAttachmentEntity.fromJson(Map<String, dynamic> json) =>
      MailAttachmentEntity(
        index: (json['index'] as num).toInt(),
        filename: json['filename'] as String? ?? 'attachment',
        contentType: json['contentType'] as String? ?? 'application/octet-stream',
        size: (json['size'] as num?)?.toInt() ?? 0,
      );
}

class MailMessageEntity {
  final int uid;
  final String from;
  final String to;
  final String subject;
  final DateTime date;
  final String? messageId;
  final String? html;
  final String text;
  final List<MailAttachmentEntity> attachments;

  MailMessageEntity({
    required this.uid,
    required this.from,
    required this.to,
    required this.subject,
    required this.date,
    this.messageId,
    this.html,
    required this.text,
    required this.attachments,
  });

  factory MailMessageEntity.fromJson(Map<String, dynamic> json) =>
      MailMessageEntity(
        uid: (json['uid'] as num).toInt(),
        from: json['from'] as String? ?? '',
        to: json['to'] as String? ?? '',
        subject: json['subject'] as String? ?? '',
        date: DateTime.tryParse(json['date'] as String? ?? '') ?? DateTime.now(),
        messageId: json['messageId'] as String?,
        html: json['html'] as String?,
        text: json['text'] as String? ?? '',
        attachments: (json['attachments'] as List? ?? [])
            .map((a) => MailAttachmentEntity.fromJson(
                Map<String, dynamic>.from(a as Map)))
            .toList(),
      );
}

class MailAppPasswordEntity {
  final String id;
  final String label;
  final DateTime? createdAt;
  final String? password; // только сразу после создания

  MailAppPasswordEntity({
    required this.id,
    required this.label,
    this.createdAt,
    this.password,
  });

  factory MailAppPasswordEntity.fromJson(Map<String, dynamic> json) =>
      MailAppPasswordEntity(
        id: json['id'] as String,
        label: json['label'] as String? ?? '',
        createdAt: DateTime.tryParse(json['createdAt'] as String? ?? ''),
        password: json['password'] as String?,
      );
}

class MailAvailabilityEntity {
  final String localpart;
  final bool available;
  final String? reason; // INVALID | RESERVED | TAKEN

  MailAvailabilityEntity({
    required this.localpart,
    required this.available,
    this.reason,
  });

  factory MailAvailabilityEntity.fromJson(Map<String, dynamic> json) =>
      MailAvailabilityEntity(
        localpart: json['localpart'] as String? ?? '',
        available: json['available'] as bool? ?? false,
        reason: json['reason'] as String?,
      );
}
```

- [x] **Step 2: `mail_remote_datasource.dart`** (паттерн messenger_remote_datasource)

```dart
import 'dart:typed_data';

import '../../../../core/api/dio_client.dart';
import '../../domain/entities/mail_entities.dart';

class MailRemoteDataSource {
  final DioClient _http;

  MailRemoteDataSource(this._http);

  Future<MailAvailabilityEntity> checkAvailability(String localpart) =>
      _http.get<MailAvailabilityEntity>(
        '/mail/availability',
        queryParameters: {'localpart': localpart},
        fromJson: (d) =>
            MailAvailabilityEntity.fromJson(Map<String, dynamic>.from(d as Map)),
      );

  Future<MailAccountEntity> createAccount(String localpart) =>
      _http.post<MailAccountEntity>(
        '/mail/account',
        data: {'localpart': localpart},
        fromJson: (d) =>
            MailAccountEntity.fromJson(Map<String, dynamic>.from(d as Map)),
      );

  Future<MailAccountEntity> getAccount() => _http.get<MailAccountEntity>(
        '/mail/account',
        fromJson: (d) =>
            MailAccountEntity.fromJson(Map<String, dynamic>.from(d as Map)),
      );

  Future<({List<MailListItemEntity> items, int? nextCursor})> getMessages(
      {int? beforeUid}) async {
    final data = await _http.get<Map<String, dynamic>>(
      '/mail/messages',
      queryParameters: {if (beforeUid != null) 'beforeUid': beforeUid},
      fromJson: (d) => Map<String, dynamic>.from(d as Map),
    );
    return (
      items: (data['items'] as List? ?? [])
          .map((m) =>
              MailListItemEntity.fromJson(Map<String, dynamic>.from(m as Map)))
          .toList(),
      nextCursor: (data['nextCursor'] as num?)?.toInt(),
    );
  }

  Future<MailMessageEntity> getMessage(int uid) =>
      _http.get<MailMessageEntity>(
        '/mail/messages/$uid',
        fromJson: (d) =>
            MailMessageEntity.fromJson(Map<String, dynamic>.from(d as Map)),
      );

  Future<Uint8List> downloadAttachment(int uid, int index) =>
      _http.getBytes('/mail/messages/$uid/attachments/$index');

  Future<void> sendMessage({
    required String to,
    required String subject,
    required String text,
    String? inReplyTo,
    List<({String filename, String contentBase64})> attachments = const [],
  }) =>
      _http.post(
        '/mail/messages',
        data: {
          'to': to,
          'subject': subject,
          'text': text,
          if (inReplyTo != null) 'inReplyTo': inReplyTo,
          if (attachments.isNotEmpty)
            'attachments': attachments
                .map((a) =>
                    {'filename': a.filename, 'contentBase64': a.contentBase64})
                .toList(),
        },
        fromJson: (d) => d,
      );

  Future<void> setSeen(int uid, bool seen) => _http.post(
        '/mail/messages/$uid/${seen ? 'read' : 'unread'}',
        data: const {},
        fromJson: (d) => d,
      );

  Future<void> deleteMessage(int uid) =>
      _http.delete('/mail/messages/$uid', fromJson: (d) => d);

  Future<MailAppPasswordEntity> createAppPassword(String label) =>
      _http.post<MailAppPasswordEntity>(
        '/mail/app-passwords',
        data: {'label': label},
        fromJson: (d) =>
            MailAppPasswordEntity.fromJson(Map<String, dynamic>.from(d as Map)),
      );

  Future<List<MailAppPasswordEntity>> listAppPasswords() =>
      _http.get<List<MailAppPasswordEntity>>(
        '/mail/app-passwords',
        fromJson: (d) => (d as List)
            .map((p) =>
                MailAppPasswordEntity.fromJson(Map<String, dynamic>.from(p as Map)))
            .toList(),
      );

  Future<void> revokeAppPassword(String id) =>
      _http.delete('/mail/app-passwords/$id', fromJson: (d) => d);
}
```

⚠️ Если у `DioClient` нет `getBytes`/`delete` — проверь `lib/core/api/dio_client.dart` и добавь недостающие методы по образцу `get` (для bytes: `Options(responseType: ResponseType.bytes)`), это единственное допустимое изменение core.

- [x] **Step 3: `i_mail_repository.dart` + `mail_repository_impl.dart`** — интерфейс повторяет datasource 1:1, impl тонко делегирует (без кэша в Phase 2):

```dart
// i_mail_repository.dart
import 'dart:typed_data';
import '../entities/mail_entities.dart';

abstract class IMailRepository {
  Future<MailAvailabilityEntity> checkAvailability(String localpart);
  Future<MailAccountEntity> createAccount(String localpart);
  Future<MailAccountEntity> getAccount();
  Future<({List<MailListItemEntity> items, int? nextCursor})> getMessages({int? beforeUid});
  Future<MailMessageEntity> getMessage(int uid);
  Future<Uint8List> downloadAttachment(int uid, int index);
  Future<void> sendMessage({
    required String to,
    required String subject,
    required String text,
    String? inReplyTo,
    List<({String filename, String contentBase64})> attachments,
  });
  Future<void> setSeen(int uid, bool seen);
  Future<void> deleteMessage(int uid);
  Future<MailAppPasswordEntity> createAppPassword(String label);
  Future<List<MailAppPasswordEntity>> listAppPasswords();
  Future<void> revokeAppPassword(String id);
}
```

```dart
// mail_repository_impl.dart
import 'dart:typed_data';
import '../../domain/entities/mail_entities.dart';
import '../../domain/repositories/i_mail_repository.dart';
import '../datasources/mail_remote_datasource.dart';

class MailRepositoryImpl implements IMailRepository {
  final MailRemoteDataSource _remote;
  MailRepositoryImpl(this._remote);

  @override
  Future<MailAvailabilityEntity> checkAvailability(String localpart) =>
      _remote.checkAvailability(localpart);
  @override
  Future<MailAccountEntity> createAccount(String localpart) =>
      _remote.createAccount(localpart);
  @override
  Future<MailAccountEntity> getAccount() => _remote.getAccount();
  @override
  Future<({List<MailListItemEntity> items, int? nextCursor})> getMessages(
          {int? beforeUid}) =>
      _remote.getMessages(beforeUid: beforeUid);
  @override
  Future<MailMessageEntity> getMessage(int uid) => _remote.getMessage(uid);
  @override
  Future<Uint8List> downloadAttachment(int uid, int index) =>
      _remote.downloadAttachment(uid, index);
  @override
  Future<void> sendMessage({
    required String to,
    required String subject,
    required String text,
    String? inReplyTo,
    List<({String filename, String contentBase64})> attachments = const [],
  }) =>
      _remote.sendMessage(
          to: to,
          subject: subject,
          text: text,
          inReplyTo: inReplyTo,
          attachments: attachments);
  @override
  Future<void> setSeen(int uid, bool seen) => _remote.setSeen(uid, seen);
  @override
  Future<void> deleteMessage(int uid) => _remote.deleteMessage(uid);
  @override
  Future<MailAppPasswordEntity> createAppPassword(String label) =>
      _remote.createAppPassword(label);
  @override
  Future<List<MailAppPasswordEntity>> listAppPasswords() =>
      _remote.listAppPasswords();
  @override
  Future<void> revokeAppPassword(String id) => _remote.revokeAppPassword(id);
}
```

- [x] **Step 4: Компиляция** — `cd ~/Downloads/taler_id_mobile/.worktrees/dev-merge && flutter analyze lib/features/mail` → no issues.

- [x] **Step 5: Commit** — `git add lib/features/mail lib/core/api && git commit -m "feat(mail): entities, datasource, repository"`

---

### Task 2: MailBloc (TDD, bloc_test)

**Files:**
- Create: `lib/features/mail/presentation/bloc/mail_event.dart`
- Create: `lib/features/mail/presentation/bloc/mail_state.dart`
- Create: `lib/features/mail/presentation/bloc/mail_bloc.dart`
- Test: `test/mail/mail_bloc_test.dart`

- [x] **Step 1: Написать падающий тест `test/mail/mail_bloc_test.dart`**

```dart
import 'dart:typed_data';

import 'package:bloc_test/bloc_test.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/features/mail/domain/entities/mail_entities.dart';
import 'package:taler_id_mobile/features/mail/domain/repositories/i_mail_repository.dart';
import 'package:taler_id_mobile/features/mail/presentation/bloc/mail_bloc.dart';
import 'package:taler_id_mobile/features/mail/presentation/bloc/mail_event.dart';
import 'package:taler_id_mobile/features/mail/presentation/bloc/mail_state.dart';

class MockMailRepository extends Mock implements IMailRepository {}

MailListItemEntity item(int uid, {bool seen = false}) => MailListItemEntity(
      uid: uid,
      from: 'Test Sender',
      fromAddress: 'sender@talerid.io',
      subject: 'Subject $uid',
      date: DateTime(2026, 7, 24),
      seen: seen,
      snippet: 'snippet',
      hasAttachments: false,
    );

void main() {
  late MockMailRepository repo;

  setUp(() => repo = MockMailRepository());

  MailBloc build() => MailBloc(repo: repo);

  group('MailInboxRequested', () {
    blocTest<MailBloc, MailState>(
      'loads first page',
      build: () {
        when(() => repo.getAccount()).thenAnswer((_) async => MailAccountEntity(
            address: 'me@talerid.io',
            localpart: 'me',
            domain: 'talerid.io',
            status: 'ACTIVE'));
        when(() => repo.getMessages(beforeUid: null))
            .thenAnswer((_) async => (items: [item(5), item(4)], nextCursor: 4));
        return build();
      },
      act: (b) => b.add(const MailInboxRequested()),
      expect: () => [
        isA<MailState>().having((s) => s.isLoading, 'loading', true),
        isA<MailState>()
            .having((s) => s.items.length, 'items', 2)
            .having((s) => s.nextCursor, 'cursor', 4)
            .having((s) => s.account?.address, 'address', 'me@talerid.io')
            .having((s) => s.isLoading, 'loading', false),
      ],
    );

    blocTest<MailBloc, MailState>(
      'no account (404) → noAccount=true, no error',
      build: () {
        when(() => repo.getAccount()).thenThrow(Exception('404'));
        return build();
      },
      act: (b) => b.add(const MailInboxRequested()),
      expect: () => [
        isA<MailState>().having((s) => s.isLoading, 'loading', true),
        isA<MailState>()
            .having((s) => s.noAccount, 'noAccount', true)
            .having((s) => s.isLoading, 'loading', false),
      ],
    );

    blocTest<MailBloc, MailState>(
      'messages error → error set',
      build: () {
        when(() => repo.getAccount()).thenAnswer((_) async => MailAccountEntity(
            address: 'me@talerid.io',
            localpart: 'me',
            domain: 'talerid.io',
            status: 'ACTIVE'));
        when(() => repo.getMessages(beforeUid: null))
            .thenThrow(Exception('network'));
        return build();
      },
      act: (b) => b.add(const MailInboxRequested()),
      expect: () => [
        isA<MailState>().having((s) => s.isLoading, 'loading', true),
        isA<MailState>()
            .having((s) => s.error, 'error', isNotNull)
            .having((s) => s.isLoading, 'loading', false),
      ],
    );
  });

  group('MailLoadMoreRequested', () {
    blocTest<MailBloc, MailState>(
      'appends next page using nextCursor',
      build: () {
        when(() => repo.getMessages(beforeUid: 4))
            .thenAnswer((_) async => (items: [item(3)], nextCursor: null));
        return build();
      },
      seed: () => MailState(items: [item(5), item(4)], nextCursor: 4),
      act: (b) => b.add(const MailLoadMoreRequested()),
      expect: () => [
        isA<MailState>().having((s) => s.isLoadingMore, 'more', true),
        isA<MailState>()
            .having((s) => s.items.length, 'items', 3)
            .having((s) => s.nextCursor, 'cursor', null),
      ],
    );
  });

  group('MailMarkSeenRequested', () {
    blocTest<MailBloc, MailState>(
      'optimistically flips seen flag',
      build: () {
        when(() => repo.setSeen(5, true)).thenAnswer((_) async {});
        return build();
      },
      seed: () => MailState(items: [item(5)]),
      act: (b) => b.add(const MailMarkSeenRequested(uid: 5, seen: true)),
      expect: () => [
        isA<MailState>().having((s) => s.items.first.seen, 'seen', true),
      ],
    );
  });

  group('MailDeleteRequested', () {
    blocTest<MailBloc, MailState>(
      'removes item from list',
      build: () {
        when(() => repo.deleteMessage(5)).thenAnswer((_) async {});
        return build();
      },
      seed: () => MailState(items: [item(5), item(4)]),
      act: (b) => b.add(const MailDeleteRequested(5)),
      expect: () => [
        isA<MailState>().having((s) => s.items.length, 'items', 1),
      ],
    );
  });
}
```

- [x] **Step 2: Убедиться, что падает** — `flutter test test/mail/mail_bloc_test.dart` → FAIL (files missing).

- [x] **Step 3: `mail_event.dart`**

```dart
import 'package:equatable/equatable.dart';

abstract class MailEvent extends Equatable {
  const MailEvent();
  @override
  List<Object?> get props => [];
}

class MailInboxRequested extends MailEvent {
  const MailInboxRequested();
}

class MailLoadMoreRequested extends MailEvent {
  const MailLoadMoreRequested();
}

class MailMarkSeenRequested extends MailEvent {
  final int uid;
  final bool seen;
  const MailMarkSeenRequested({required this.uid, required this.seen});
  @override
  List<Object?> get props => [uid, seen];
}

class MailDeleteRequested extends MailEvent {
  final int uid;
  const MailDeleteRequested(this.uid);
  @override
  List<Object?> get props => [uid];
}
```

- [x] **Step 4: `mail_state.dart`**

```dart
import 'package:equatable/equatable.dart';

import '../../domain/entities/mail_entities.dart';

class MailState extends Equatable {
  final MailAccountEntity? account;
  final List<MailListItemEntity> items;
  final int? nextCursor;
  final bool isLoading;
  final bool isLoadingMore;
  final bool noAccount;
  final String? error;

  const MailState({
    this.account,
    this.items = const [],
    this.nextCursor,
    this.isLoading = false,
    this.isLoadingMore = false,
    this.noAccount = false,
    this.error,
  });

  MailState copyWith({
    MailAccountEntity? account,
    List<MailListItemEntity>? items,
    int? nextCursor,
    bool clearCursor = false,
    bool? isLoading,
    bool? isLoadingMore,
    bool? noAccount,
    String? error,
    bool clearError = false,
  }) =>
      MailState(
        account: account ?? this.account,
        items: items ?? this.items,
        nextCursor: clearCursor ? null : (nextCursor ?? this.nextCursor),
        isLoading: isLoading ?? this.isLoading,
        isLoadingMore: isLoadingMore ?? this.isLoadingMore,
        noAccount: noAccount ?? this.noAccount,
        error: clearError ? null : (error ?? this.error),
      );

  @override
  List<Object?> get props =>
      [account, items, nextCursor, isLoading, isLoadingMore, noAccount, error];
}
```

- [x] **Step 5: `mail_bloc.dart`**

```dart
import 'package:flutter_bloc/flutter_bloc.dart';

import '../../domain/repositories/i_mail_repository.dart';
import 'mail_event.dart';
import 'mail_state.dart';

class MailBloc extends Bloc<MailEvent, MailState> {
  final IMailRepository _repo;

  MailBloc({required IMailRepository repo})
      : _repo = repo,
        super(const MailState()) {
    on<MailInboxRequested>(_onInboxRequested);
    on<MailLoadMoreRequested>(_onLoadMore);
    on<MailMarkSeenRequested>(_onMarkSeen);
    on<MailDeleteRequested>(_onDelete);
  }

  Future<void> _onInboxRequested(
      MailInboxRequested event, Emitter<MailState> emit) async {
    emit(state.copyWith(isLoading: true, clearError: true, noAccount: false));
    try {
      final account = await _repo.getAccount();
      final page = await _repo.getMessages(beforeUid: null);
      emit(state.copyWith(
        account: account,
        items: page.items,
        nextCursor: page.nextCursor,
        clearCursor: page.nextCursor == null,
        isLoading: false,
      ));
    } catch (e) {
      // 404 = ящика нет (старый юзер, ещё не выбрал адрес)
      final msg = e.toString();
      if (msg.contains('404') || msg.contains('mail_account_not_found')) {
        emit(state.copyWith(noAccount: true, isLoading: false));
      } else {
        emit(state.copyWith(error: msg, isLoading: false));
      }
    }
  }

  Future<void> _onLoadMore(
      MailLoadMoreRequested event, Emitter<MailState> emit) async {
    final cursor = state.nextCursor;
    if (cursor == null || state.isLoadingMore) return;
    emit(state.copyWith(isLoadingMore: true));
    try {
      final page = await _repo.getMessages(beforeUid: cursor);
      emit(state.copyWith(
        items: [...state.items, ...page.items],
        nextCursor: page.nextCursor,
        clearCursor: page.nextCursor == null,
        isLoadingMore: false,
      ));
    } catch (e) {
      emit(state.copyWith(error: e.toString(), isLoadingMore: false));
    }
  }

  Future<void> _onMarkSeen(
      MailMarkSeenRequested event, Emitter<MailState> emit) async {
    emit(state.copyWith(
      items: state.items
          .map((m) => m.uid == event.uid ? m.copyWith(seen: event.seen) : m)
          .toList(),
    ));
    try {
      await _repo.setSeen(event.uid, event.seen);
    } catch (_) {
      // тихий откат не делаем — при следующем refresh придёт серверное состояние
    }
  }

  Future<void> _onDelete(
      MailDeleteRequested event, Emitter<MailState> emit) async {
    emit(state.copyWith(
      items: state.items.where((m) => m.uid != event.uid).toList(),
    ));
    try {
      await _repo.deleteMessage(event.uid);
    } catch (e) {
      emit(state.copyWith(error: e.toString()));
    }
  }
}
```

- [x] **Step 6: Тесты зелёные** — `flutter test test/mail/mail_bloc_test.dart` → all passed.

- [x] **Step 7: Commit** — `git add lib/features/mail test/mail && git commit -m "feat(mail): MailBloc with inbox pagination and flags"`

---

### Task 3: DI + routes + l10n-строки

**Files:**
- Modify: `lib/core/di/service_locator.dart`
- Modify: `lib/core/router/app_router.dart` + файл RouteConstants (`grep -rn "class RouteConstants" lib/` — фактический путь)
- Modify: `lib/l10n/app_en.arb`, `lib/l10n/app_ru.arb`

- [x] **Step 1: DI** — в `setupDependencies` рядом с messenger-блоком:

```dart
// Mail
sl.registerLazySingleton<MailRemoteDataSource>(
  () => MailRemoteDataSource(sl<DioClient>()),
);
sl.registerLazySingleton<IMailRepository>(
  () => MailRepositoryImpl(sl<MailRemoteDataSource>()),
);
sl.registerFactory<MailBloc>(() => MailBloc(repo: sl<IMailRepository>()));
```

(`registerFactory` для блока — состояние inbox не нужно держать глобально; экраны создают через `BlocProvider(create: ...)`.)

- [x] **Step 2: RouteConstants + routes.** В RouteConstants добавить:

```dart
static const String mail = '/mail';
static const String mailAddressSetup = '/mail/setup';
```

В `app_router.dart` внутрь ShellRoute.routes:

```dart
GoRoute(
  path: RouteConstants.mail,
  builder: (_, __) => const MailInboxScreen(),
  routes: [
    GoRoute(path: 'compose', builder: (_, state) {
      final extra = state.extra as Map<String, dynamic>?;
      return MailComposeScreen(
        replyTo: extra?['replyTo'] as String?,
        replySubject: extra?['replySubject'] as String?,
        replyMessageId: extra?['replyMessageId'] as String?,
      );
    }),
    GoRoute(path: 'app-passwords', builder: (_, __) => const MailAppPasswordsScreen()),
    GoRoute(path: ':uid', builder: (_, state) =>
        MailDetailScreen(uid: int.parse(state.pathParameters['uid']!))),
  ],
),
```

И ВНЕ ShellRoute (fullscreen, без нижней навигации) — экран выбора адреса:

```dart
GoRoute(
  path: RouteConstants.mailAddressSetup,
  builder: (_, __) => const MailAddressSetupScreen(),
),
```

⚠️ Порядок вложенных routes важен: `compose` и `app-passwords` — ДО `:uid`, иначе go_router сматчит их как uid.

- [x] **Step 3: l10n.** В `app_en.arb` добавить (и русские аналоги в `app_ru.arb`):

```json
"mailTitle": "Mail",
"mailSectionHeader": "Mail",
"mailInboxEmpty": "No emails yet",
"mailNoAccountTitle": "Choose your @talerid.io address",
"mailNoAccountBody": "Create your personal email address to send and receive mail.",
"mailChooseAddress": "Choose address",
"mailAddressHint": "username",
"mailAddressTaken": "This address is already taken",
"mailAddressInvalid": "Only latin letters, digits, dot, dash, underscore (3–64 chars)",
"mailAddressReserved": "This name is reserved",
"mailAddressAvailable": "Address is available",
"mailCreateAddress": "Create address",
"mailSetupLater": "Later",
"mailCompose": "New email",
"mailTo": "To",
"mailSubject": "Subject",
"mailBody": "Message",
"mailSend": "Send",
"mailSent": "Email sent",
"mailReply": "Reply",
"mailDelete": "Delete",
"mailMarkUnread": "Mark as unread",
"mailAttachments": "Attachments",
"mailAttachFile": "Attach file",
"mailAppPasswords": "App passwords",
"mailAppPasswordsHint": "Use app passwords to connect Apple Mail, Gmail or other IMAP clients.",
"mailAppPasswordLabel": "Name (e.g. iPhone Apple Mail)",
"mailAppPasswordCreate": "Create password",
"mailAppPasswordShownOnce": "Save this password now — it is shown only once.",
"mailAppPasswordCopied": "Password copied",
"mailAppPasswordRevoke": "Revoke",
"mailClientSettingsTitle": "Client settings",
"mailSendLimitReached": "Daily send limit reached",
"mailQuotaTitle": "Mailbox"
```

Русские значения: «Почта», «Писем пока нет», «Выберите ваш адрес @talerid.io», «Создайте личный email-адрес для отправки и получения почты», «Выбрать адрес», «имя», «Адрес уже занят», «Только латиница, цифры, точка, дефис, подчёркивание (3–64)», «Это имя зарезервировано», «Адрес свободен», «Создать адрес», «Позже», «Новое письмо», «Кому», «Тема», «Сообщение», «Отправить», «Письмо отправлено», «Ответить», «Удалить», «Отметить непрочитанным», «Вложения», «Прикрепить файл», «Пароли приложений», «Используйте пароли приложений для подключения Apple Mail, Gmail и других IMAP-клиентов.», «Название (напр. iPhone Apple Mail)», «Создать пароль», «Сохраните пароль сейчас — он показывается только один раз.», «Пароль скопирован», «Отозвать», «Настройки клиента», «Дневной лимит отправки исчерпан», «Почтовый ящик».

Затем `flutter gen-l10n` (или `flutter pub get` — как принято в репо, генерация в build).

- [x] **Step 4: Commit** — `git add lib/core lib/l10n && git commit -m "feat(mail): DI, routes, l10n strings"` (может не скомпилироваться до Task 4-6 — если analyze падает на несуществующих экранах, создать в этом же коммите пустые заглушки экранов `Scaffold(body: SizedBox())` в файлах из Task 4-6 и наполнить их там).

---

### Task 4: Экран выбора адреса + гейт после логина

**Files:**
- Create: `lib/features/mail/presentation/screens/mail_address_setup_screen.dart`
- Modify: `lib/core/router/post_login_redirect.dart`
- Modify: `lib/core/storage/secure_storage_service.dart` (флаг «отложил настройку»)

- [x] **Step 1: Флаг в SecureStorageService** (по образцу `isOnboardingSeen`):

```dart
static const _mailSetupDismissedKey = 'mail_setup_dismissed';

Future<bool> get isMailSetupDismissed async =>
    (await read(_mailSetupDismissedKey)) == 'true';

Future<void> setMailSetupDismissed() => write(_mailSetupDismissedKey, 'true');
```

(Сверь фактические имена методов read/write в этом сервисе и повтори соседний паттерн.)

- [x] **Step 2: Гейт в `post_login_redirect.dart`.** После проверки onboarding, перед переходом на defaultRoute:

```dart
// Гейт выбора почтового адреса: показываем один раз после онбординга,
// пока юзер не создал ящик или явно не нажал «Позже».
if (seen) {
  final dismissed = await storage.isMailSetupDismissed;
  if (!dismissed) {
    bool hasMailbox = false;
    try {
      await sl<IMailRepository>().getAccount();
      hasMailbox = true;
    } catch (_) {
      hasMailbox = false; // 404 или сеть — покажем экран, там есть «Позже»
    }
    if (!context.mounted) return;
    if (!hasMailbox) {
      context.go(RouteConstants.mailAddressSetup);
      return;
    }
  }
}
```

- [x] **Step 3: `mail_address_setup_screen.dart`** — fullscreen: заголовок `l10n.mailNoAccountTitle`, поле localpart с суффиксом `@talerid.io` (домен показывать из ответа availability не нужно — используй статический текст `@' + domain`; домен возьми из первого успешного `checkAvailability` ответа? Нет — домен известен только бэкенду; показывай просто `@…` до первого ответа, а после создания покажи полный `account.address`). Debounce 400мс на ввод → `checkAvailability`; под полем — статус (available/taken/invalid/reserved из l10n). Кнопка `mailCreateAddress` активна только при `available`. Кнопка «Позже» → `storage.setMailSetupDismissed()` → `postLoginNavigate`-подобный переход на дефолтный route.

```dart
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_gen/gen_l10n/app_localizations.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/di/service_locator.dart';
import '../../../../core/router/route_constants.dart';
import '../../../../core/storage/secure_storage_service.dart';
import '../../../../core/utils/platform_utils.dart';
import '../../domain/repositories/i_mail_repository.dart';

class MailAddressSetupScreen extends StatefulWidget {
  const MailAddressSetupScreen({super.key});

  @override
  State<MailAddressSetupScreen> createState() => _MailAddressSetupScreenState();
}

class _MailAddressSetupScreenState extends State<MailAddressSetupScreen> {
  final _controller = TextEditingController();
  Timer? _debounce;
  String? _statusKey; // available | taken | invalid | reserved
  bool _checking = false;
  bool _creating = false;
  String _checkedLocalpart = '';

  void _onChanged(String value) {
    _debounce?.cancel();
    setState(() => _statusKey = null);
    final lp = value.trim().toLowerCase();
    if (lp.length < 3) return;
    _debounce = Timer(const Duration(milliseconds: 400), () async {
      setState(() => _checking = true);
      try {
        final res = await sl<IMailRepository>().checkAvailability(lp);
        if (!mounted) return;
        setState(() {
          _checkedLocalpart = res.localpart;
          _statusKey = res.available
              ? 'available'
              : (res.reason ?? 'INVALID').toLowerCase();
          _checking = false;
        });
      } catch (_) {
        if (mounted) setState(() => _checking = false);
      }
    });
  }

  Future<void> _create() async {
    setState(() => _creating = true);
    try {
      await sl<IMailRepository>().createAccount(_checkedLocalpart);
      if (!mounted) return;
      _goNext();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _creating = false;
        _statusKey = 'taken';
      });
    }
  }

  Future<void> _later() async {
    await sl<SecureStorageService>().setMailSetupDismissed();
    if (mounted) _goNext();
  }

  void _goNext() {
    context.go(PlatformUtils.instance.isDesktop
        ? RouteConstants.messenger
        : RouteConstants.assistant);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final statusText = switch (_statusKey) {
      'available' => l10n.mailAddressAvailable,
      'taken' => l10n.mailAddressTaken,
      'reserved' => l10n.mailAddressReserved,
      'invalid' => l10n.mailAddressInvalid,
      _ => null,
    };
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Spacer(),
              Icon(Icons.alternate_email, size: 56,
                  color: Theme.of(context).colorScheme.primary),
              const SizedBox(height: 16),
              Text(l10n.mailNoAccountTitle,
                  style: Theme.of(context).textTheme.headlineSmall,
                  textAlign: TextAlign.center),
              const SizedBox(height: 8),
              Text(l10n.mailNoAccountBody,
                  style: Theme.of(context).textTheme.bodyMedium,
                  textAlign: TextAlign.center),
              const SizedBox(height: 24),
              TextField(
                controller: _controller,
                autofocus: true,
                autocorrect: false,
                decoration: InputDecoration(
                  hintText: l10n.mailAddressHint,
                  suffixText: '@talerid.io',
                  helperText: statusText,
                  helperStyle: TextStyle(
                    color: _statusKey == 'available'
                        ? Colors.greenAccent
                        : Theme.of(context).colorScheme.error,
                  ),
                  suffixIcon: _checking
                      ? const Padding(
                          padding: EdgeInsets.all(12),
                          child: SizedBox(width: 16, height: 16,
                              child: CircularProgressIndicator(strokeWidth: 2)),
                        )
                      : null,
                ),
                onChanged: _onChanged,
              ),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: _statusKey == 'available' && !_creating ? _create : null,
                child: _creating
                    ? const SizedBox(width: 20, height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : Text(l10n.mailCreateAddress),
              ),
              TextButton(onPressed: _later, child: Text(l10n.mailSetupLater)),
              const Spacer(),
            ],
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _controller.dispose();
    super.dispose();
  }
}
```

⚠️ Суффикс `@talerid.io` — только визуальный дефолт; фактический домен возвращает бэкенд (`account.address`). На dev-flavor будет `@mail-dev.taler.tirol` — не критично для UX, но если просто: после первого availability-ответа домен неизвестен, оставить как есть.

- [x] **Step 4: `flutter analyze` чисто, commit** — `git add lib/ && git commit -m "feat(mail): address setup screen + post-login gate"`

---

### Task 5: Inbox + Detail + Compose экраны

**Files:**
- Create: `lib/features/mail/presentation/screens/mail_inbox_screen.dart`
- Create: `lib/features/mail/presentation/screens/mail_detail_screen.dart`
- Create: `lib/features/mail/presentation/screens/mail_compose_screen.dart`
- Create: `lib/features/mail/presentation/widgets/mail_tile.dart`

- [x] **Step 1: `mail_tile.dart`**

```dart
import 'package:flutter/material.dart';

import '../../domain/entities/mail_entities.dart';

class MailTile extends StatelessWidget {
  final MailListItemEntity item;
  final VoidCallback onTap;

  const MailTile({super.key, required this.item, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final bold = item.seen ? FontWeight.normal : FontWeight.bold;
    return ListTile(
      onTap: onTap,
      leading: CircleAvatar(
        child: Text(item.from.isNotEmpty ? item.from[0].toUpperCase() : '?'),
      ),
      title: Text(item.from,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(fontWeight: bold)),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(item.subject,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(fontWeight: bold)),
          Text(item.snippet,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall),
        ],
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          Text(_formatDate(item.date), style: theme.textTheme.bodySmall),
          if (item.hasAttachments) const Icon(Icons.attach_file, size: 16),
        ],
      ),
    );
  }

  String _formatDate(DateTime d) {
    final now = DateTime.now();
    if (d.year == now.year && d.month == now.month && d.day == now.day) {
      return '${d.hour.toString().padLeft(2, '0')}:${d.minute.toString().padLeft(2, '0')}';
    }
    return '${d.day.toString().padLeft(2, '0')}.${d.month.toString().padLeft(2, '0')}';
  }
}
```

- [x] **Step 2: `mail_inbox_screen.dart`** — BlocProvider(create: sl<MailBloc>()..add(MailInboxRequested())), RefreshIndicator + ListView с MailTile, скролл-триггер `MailLoadMoreRequested` за 200px до конца, FAB compose, состояния: loading → spinner; noAccount → CTA `context.go(RouteConstants.mailAddressSetup)`; error → текст+retry; empty → `l10n.mailInboxEmpty`. AppBar title `l10n.mailTitle` + subtitle-адрес `state.account?.address`, action-иконка `Icons.key` → `context.push('/mail/app-passwords')`.

```dart
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_gen/gen_l10n/app_localizations.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/di/service_locator.dart';
import '../../../../core/router/route_constants.dart';
import '../bloc/mail_bloc.dart';
import '../bloc/mail_event.dart';
import '../bloc/mail_state.dart';
import '../widgets/mail_tile.dart';

class MailInboxScreen extends StatelessWidget {
  const MailInboxScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return BlocProvider(
      create: (_) => sl<MailBloc>()..add(const MailInboxRequested()),
      child: const _MailInboxView(),
    );
  }
}

class _MailInboxView extends StatelessWidget {
  const _MailInboxView();

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return BlocBuilder<MailBloc, MailState>(
      builder: (context, state) {
        return Scaffold(
          appBar: AppBar(
            title: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(l10n.mailTitle),
                if (state.account != null)
                  Text(state.account!.address,
                      style: Theme.of(context).textTheme.bodySmall),
              ],
            ),
            actions: [
              IconButton(
                icon: const Icon(Icons.key_outlined),
                onPressed: () => context.push('${RouteConstants.mail}/app-passwords'),
              ),
            ],
          ),
          floatingActionButton: state.account == null
              ? null
              : FloatingActionButton(
                  onPressed: () => context.push('${RouteConstants.mail}/compose'),
                  child: const Icon(Icons.edit_outlined),
                ),
          body: _body(context, state, l10n),
        );
      },
    );
  }

  Widget _body(BuildContext context, MailState state, AppLocalizations l10n) {
    if (state.isLoading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (state.noAccount) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(l10n.mailNoAccountTitle),
            const SizedBox(height: 12),
            FilledButton(
              onPressed: () => context.go(RouteConstants.mailAddressSetup),
              child: Text(l10n.mailChooseAddress),
            ),
          ],
        ),
      );
    }
    if (state.error != null && state.items.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.cloud_off_outlined, size: 40),
            const SizedBox(height: 8),
            TextButton(
              onPressed: () =>
                  context.read<MailBloc>().add(const MailInboxRequested()),
              child: const Text('Retry'),
            ),
          ],
        ),
      );
    }
    if (state.items.isEmpty) {
      return Center(child: Text(l10n.mailInboxEmpty));
    }
    return RefreshIndicator(
      onRefresh: () async =>
          context.read<MailBloc>().add(const MailInboxRequested()),
      child: NotificationListener<ScrollNotification>(
        onNotification: (n) {
          if (n.metrics.extentAfter < 200) {
            context.read<MailBloc>().add(const MailLoadMoreRequested());
          }
          return false;
        },
        child: ListView.separated(
          physics: const AlwaysScrollableScrollPhysics(),
          itemCount: state.items.length + (state.isLoadingMore ? 1 : 0),
          separatorBuilder: (_, __) => const Divider(height: 1),
          itemBuilder: (context, i) {
            if (i >= state.items.length) {
              return const Padding(
                padding: EdgeInsets.all(16),
                child: Center(child: CircularProgressIndicator()),
              );
            }
            final item = state.items[i];
            return Dismissible(
              key: ValueKey(item.uid),
              direction: DismissDirection.endToStart,
              background: Container(
                color: Theme.of(context).colorScheme.error,
                alignment: Alignment.centerRight,
                padding: const EdgeInsets.only(right: 16),
                child: const Icon(Icons.delete_outline),
              ),
              onDismissed: (_) =>
                  context.read<MailBloc>().add(MailDeleteRequested(item.uid)),
              child: MailTile(
                item: item,
                onTap: () {
                  context.read<MailBloc>().add(
                      MailMarkSeenRequested(uid: item.uid, seen: true));
                  context.push('${RouteConstants.mail}/${item.uid}');
                },
              ),
            );
          },
        ),
      ),
    );
  }
}
```

- [x] **Step 3: `mail_detail_screen.dart`** — свой локальный fetch (без глобального блока): `FutureBuilder(sl<IMailRepository>().getMessage(uid))`. HTML → `WebViewController..loadHtmlString` в тёмной обёртке; если html==null → SelectableText(text). Вложения — чипы: тап → `downloadAttachment` → `getTemporaryDirectory()` (path_provider) → `OpenFilex.open(path)`. AppBar actions: reply (push compose с extra `{replyTo: fromAddress-часть, replySubject: 'Re: '+subject, replyMessageId: messageId}`), delete (repo.deleteMessage → pop), mark-unread (repo.setSeen(uid,false) → pop).

```dart
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_gen/gen_l10n/app_localizations.dart';
import 'package:go_router/go_router.dart';
import 'package:open_filex/open_filex.dart';
import 'package:path_provider/path_provider.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../../core/di/service_locator.dart';
import '../../../../core/router/route_constants.dart';
import '../../domain/entities/mail_entities.dart';
import '../../domain/repositories/i_mail_repository.dart';

class MailDetailScreen extends StatefulWidget {
  final int uid;
  const MailDetailScreen({super.key, required this.uid});

  @override
  State<MailDetailScreen> createState() => _MailDetailScreenState();
}

class _MailDetailScreenState extends State<MailDetailScreen> {
  late final Future<MailMessageEntity> _future =
      sl<IMailRepository>().getMessage(widget.uid);

  Future<void> _openAttachment(MailAttachmentEntity att) async {
    final bytes =
        await sl<IMailRepository>().downloadAttachment(widget.uid, att.index);
    final dir = await getTemporaryDirectory();
    final file = File('${dir.path}/${att.filename}');
    await file.writeAsBytes(bytes);
    await OpenFilex.open(file.path);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return FutureBuilder<MailMessageEntity>(
      future: _future,
      builder: (context, snap) {
        final msg = snap.data;
        return Scaffold(
          appBar: AppBar(
            title: Text(msg?.subject ?? '', maxLines: 1,
                overflow: TextOverflow.ellipsis),
            actions: msg == null
                ? null
                : [
                    IconButton(
                      icon: const Icon(Icons.reply_outlined),
                      tooltip: l10n.mailReply,
                      onPressed: () => context.push(
                        '${RouteConstants.mail}/compose',
                        extra: {
                          'replyTo': _extractAddress(msg.from),
                          'replySubject': msg.subject.startsWith('Re:')
                              ? msg.subject
                              : 'Re: ${msg.subject}',
                          'replyMessageId': msg.messageId,
                        },
                      ),
                    ),
                    IconButton(
                      icon: const Icon(Icons.mark_email_unread_outlined),
                      tooltip: l10n.mailMarkUnread,
                      onPressed: () async {
                        await sl<IMailRepository>().setSeen(widget.uid, false);
                        if (context.mounted) context.pop();
                      },
                    ),
                    IconButton(
                      icon: const Icon(Icons.delete_outline),
                      tooltip: l10n.mailDelete,
                      onPressed: () async {
                        await sl<IMailRepository>().deleteMessage(widget.uid);
                        if (context.mounted) context.pop();
                      },
                    ),
                  ],
          ),
          body: snap.hasError
              ? const Center(child: Icon(Icons.cloud_off_outlined, size: 40))
              : msg == null
                  ? const Center(child: CircularProgressIndicator())
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Padding(
                          padding: const EdgeInsets.all(16),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(msg.from,
                                  style:
                                      Theme.of(context).textTheme.titleSmall),
                              Text('${l10n.mailTo}: ${msg.to}',
                                  style: Theme.of(context).textTheme.bodySmall),
                              Text(msg.date.toLocal().toString().substring(0, 16),
                                  style: Theme.of(context).textTheme.bodySmall),
                            ],
                          ),
                        ),
                        if (msg.attachments.isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 12),
                            child: Wrap(
                              spacing: 8,
                              children: msg.attachments
                                  .map((a) => ActionChip(
                                        avatar: const Icon(Icons.attach_file,
                                            size: 16),
                                        label: Text(a.filename,
                                            overflow: TextOverflow.ellipsis),
                                        onPressed: () => _openAttachment(a),
                                      ))
                                  .toList(),
                            ),
                          ),
                        const Divider(),
                        Expanded(child: _MailBody(msg: msg)),
                      ],
                    ),
        );
      },
    );
  }

  String _extractAddress(String from) {
    final m = RegExp(r'<([^>]+)>').firstMatch(from);
    return m?.group(1) ?? from.trim();
  }
}

class _MailBody extends StatefulWidget {
  final MailMessageEntity msg;
  const _MailBody({required this.msg});

  @override
  State<_MailBody> createState() => _MailBodyState();
}

class _MailBodyState extends State<_MailBody> {
  WebViewController? _controller;

  @override
  void initState() {
    super.initState();
    final html = widget.msg.html;
    if (html != null && html.isNotEmpty) {
      _controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.disabled)
        ..loadHtmlString('''
<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{background:#121212;color:#e6e6e6;font-family:-apple-system,Roboto,sans-serif;margin:16px;word-break:break-word}a{color:#8ab4f8}</style>
</head><body>$html</body></html>''');
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_controller != null) return WebViewWidget(controller: _controller!);
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: SelectableText(widget.msg.text),
    );
  }
}
```

⚠️ `webview_flutter` не работает на desktop (macOS/Windows/Linux). Гейт: `if (PlatformUtils.instance.isDesktop || html == null) → SelectableText(text)` — на десктопе показываем plain-text вариант (у бэкенда text есть всегда). Добавь этот гейт в `initState`.

- [x] **Step 4: `mail_compose_screen.dart`** — поля to/subject/body, кнопка attach (file_picker, суммарно ≤10MB, файлы копятся чипами), отправка через `sl<IMailRepository>().sendMessage(...)` → SnackBar `l10n.mailSent` → pop. 429/`mail_send_daily_limit` в ошибке → SnackBar `l10n.mailSendLimitReached`.

```dart
import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_gen/gen_l10n/app_localizations.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/di/service_locator.dart';
import '../../domain/repositories/i_mail_repository.dart';

class MailComposeScreen extends StatefulWidget {
  final String? replyTo;
  final String? replySubject;
  final String? replyMessageId;

  const MailComposeScreen(
      {super.key, this.replyTo, this.replySubject, this.replyMessageId});

  @override
  State<MailComposeScreen> createState() => _MailComposeScreenState();
}

class _MailComposeScreenState extends State<MailComposeScreen> {
  late final _to = TextEditingController(text: widget.replyTo ?? '');
  late final _subject = TextEditingController(text: widget.replySubject ?? '');
  final _body = TextEditingController();
  final List<({String filename, List<int> bytes})> _attachments = [];
  bool _sending = false;

  static const _maxTotalBytes = 10 * 1024 * 1024;

  int get _totalBytes =>
      _attachments.fold(0, (s, a) => s + a.bytes.length);

  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles(withData: true);
    final file = result?.files.firstOrNull;
    if (file?.bytes == null) return;
    if (_totalBytes + file!.bytes!.length > _maxTotalBytes) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('≤ 10 MB')));
      }
      return;
    }
    setState(() => _attachments.add((filename: file.name, bytes: file.bytes!)));
  }

  Future<void> _send() async {
    final l10n = AppLocalizations.of(context)!;
    if (_to.text.trim().isEmpty || _sending) return;
    setState(() => _sending = true);
    try {
      await sl<IMailRepository>().sendMessage(
        to: _to.text.trim(),
        subject: _subject.text.trim(),
        text: _body.text,
        inReplyTo: widget.replyMessageId,
        attachments: _attachments
            .map((a) =>
                (filename: a.filename, contentBase64: base64Encode(a.bytes)))
            .toList(),
      );
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(l10n.mailSent)));
      context.pop();
    } catch (e) {
      if (!mounted) return;
      setState(() => _sending = false);
      final limit = e.toString().contains('mail_send_daily_limit') ||
          e.toString().contains('429');
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content:
              Text(limit ? l10n.mailSendLimitReached : e.toString())));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.mailCompose),
        actions: [
          IconButton(
              icon: const Icon(Icons.attach_file), onPressed: _pickFile),
          IconButton(
            icon: _sending
                ? const SizedBox(width: 20, height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.send_outlined),
            onPressed: _send,
          ),
        ],
      ),
      body: Column(
        children: [
          TextField(
            controller: _to,
            keyboardType: TextInputType.emailAddress,
            autocorrect: false,
            decoration: InputDecoration(
                labelText: l10n.mailTo,
                contentPadding: const EdgeInsets.symmetric(horizontal: 16)),
          ),
          const Divider(height: 1),
          TextField(
            controller: _subject,
            decoration: InputDecoration(
                labelText: l10n.mailSubject,
                contentPadding: const EdgeInsets.symmetric(horizontal: 16)),
          ),
          const Divider(height: 1),
          if (_attachments.isNotEmpty)
            Padding(
              padding: const EdgeInsets.all(8),
              child: Wrap(
                spacing: 8,
                children: [
                  for (var i = 0; i < _attachments.length; i++)
                    Chip(
                      label: Text(_attachments[i].filename,
                          overflow: TextOverflow.ellipsis),
                      onDeleted: () =>
                          setState(() => _attachments.removeAt(i)),
                    ),
                ],
              ),
            ),
          Expanded(
            child: TextField(
              controller: _body,
              maxLines: null,
              expands: true,
              textAlignVertical: TextAlignVertical.top,
              decoration: InputDecoration(
                  hintText: l10n.mailBody,
                  contentPadding: const EdgeInsets.all(16),
                  border: InputBorder.none),
            ),
          ),
        ],
      ),
    );
  }
}
```

- [x] **Step 5:** `flutter analyze lib/features/mail` чисто; `flutter test test/mail/` зелёный. Commit: `git add lib/features/mail && git commit -m "feat(mail): inbox, detail, compose screens"`

---

### Task 6: App-пароли: экран + вход из Settings

**Files:**
- Create: `lib/features/mail/presentation/screens/mail_app_passwords_screen.dart`
- Modify: `lib/features/settings/presentation/screens/settings_screen.dart`

- [x] **Step 1: `mail_app_passwords_screen.dart`** — StatefulWidget, локальный fetch. Верх: карточка `l10n.mailClientSettingsTitle` с host/993/465/login (из `getAccount().clientSettings`) + hint `l10n.mailAppPasswordsHint`. Список паролей (label, createdAt, кнопка revoke с confirm-диалогом). FAB → диалог с полем label → `createAppPassword` → **модалка одноразового показа**: крупный моноширинный пароль + кнопка copy (`Clipboard.setData` + SnackBar `mailAppPasswordCopied`) + текст `mailAppPasswordShownOnce` + параметры подключения.

```dart
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_gen/gen_l10n/app_localizations.dart';

import '../../../../core/di/service_locator.dart';
import '../../domain/entities/mail_entities.dart';
import '../../domain/repositories/i_mail_repository.dart';

class MailAppPasswordsScreen extends StatefulWidget {
  const MailAppPasswordsScreen({super.key});

  @override
  State<MailAppPasswordsScreen> createState() => _MailAppPasswordsScreenState();
}

class _MailAppPasswordsScreenState extends State<MailAppPasswordsScreen> {
  List<MailAppPasswordEntity> _items = [];
  MailAccountEntity? _account;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final repo = sl<IMailRepository>();
      final account = await repo.getAccount();
      final items = await repo.listAppPasswords();
      if (!mounted) return;
      setState(() {
        _account = account;
        _items = items;
        _loading = false;
      });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _create() async {
    final l10n = AppLocalizations.of(context)!;
    final controller = TextEditingController();
    final label = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.mailAppPasswordCreate),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: InputDecoration(hintText: l10n.mailAppPasswordLabel),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, controller.text.trim()),
              child: Text(l10n.mailAppPasswordCreate)),
        ],
      ),
    );
    if (label == null || label.isEmpty) return;
    final created = await sl<IMailRepository>().createAppPassword(label);
    await _load();
    if (!mounted || created.password == null) return;
    _showPasswordOnce(created);
  }

  void _showPasswordOnce(MailAppPasswordEntity created) {
    final l10n = AppLocalizations.of(context)!;
    final settings = _account?.clientSettings;
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(created.label,
                style: Theme.of(ctx).textTheme.titleMedium,
                textAlign: TextAlign.center),
            const SizedBox(height: 12),
            SelectableText(
              created.password!,
              textAlign: TextAlign.center,
              style: const TextStyle(
                  fontFamily: 'monospace', fontSize: 20, letterSpacing: 1.5),
            ),
            const SizedBox(height: 8),
            Text(l10n.mailAppPasswordShownOnce,
                style: Theme.of(ctx).textTheme.bodySmall,
                textAlign: TextAlign.center),
            const SizedBox(height: 12),
            FilledButton.icon(
              icon: const Icon(Icons.copy),
              label: Text(l10n.mailAppPasswordCopied),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: created.password!));
                ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(l10n.mailAppPasswordCopied)));
              },
            ),
            if (settings != null) ...[
              const SizedBox(height: 16),
              Text(l10n.mailClientSettingsTitle,
                  style: Theme.of(ctx).textTheme.titleSmall),
              Text('IMAP: ${settings.host}:${settings.imapPort} (SSL)\n'
                  'SMTP: ${settings.host}:${settings.smtpPort} (SSL)\n'
                  'Login: ${settings.login}'),
            ],
            const SizedBox(height: 12),
          ],
        ),
      ),
    );
  }

  Future<void> _revoke(MailAppPasswordEntity p) async {
    final l10n = AppLocalizations.of(context)!;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('${l10n.mailAppPasswordRevoke}: ${p.label}?'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: Text(l10n.mailAppPasswordRevoke)),
        ],
      ),
    );
    if (ok != true) return;
    await sl<IMailRepository>().revokeAppPassword(p.id);
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final settings = _account?.clientSettings;
    return Scaffold(
      appBar: AppBar(title: Text(l10n.mailAppPasswords)),
      floatingActionButton: FloatingActionButton(
          onPressed: _create, child: const Icon(Icons.add)),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                Text(l10n.mailAppPasswordsHint,
                    style: Theme.of(context).textTheme.bodySmall),
                if (settings != null)
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: Text(
                          '${l10n.mailClientSettingsTitle}\n'
                          'IMAP: ${settings.host}:${settings.imapPort} (SSL)\n'
                          'SMTP: ${settings.host}:${settings.smtpPort} (SSL)\n'
                          'Login: ${settings.login}'),
                    ),
                  ),
                const SizedBox(height: 8),
                ..._items.map((p) => ListTile(
                      leading: const Icon(Icons.key_outlined),
                      title: Text(p.label),
                      subtitle: p.createdAt != null
                          ? Text(p.createdAt!.toLocal().toString().substring(0, 16))
                          : null,
                      trailing: IconButton(
                        icon: const Icon(Icons.delete_outline),
                        onPressed: () => _revoke(p),
                      ),
                    )),
              ],
            ),
    );
  }
}
```

- [x] **Step 2: Settings-секция.** В `settings_screen.dart` по паттерну существующих секций (`_sectionHeader` + `AppCard` + `_navTile`) добавить перед секцией Billing:

```dart
_sectionHeader(l10n.mailSectionHeader),
AppCard(
  child: Column(
    children: [
      _navTile(
        icon: Icons.mail_outline,
        iconColor: AppColors.of(context).primary,
        title: l10n.mailTitle,
        onTap: () => context.push(RouteConstants.mail),
      ),
      Divider(color: AppColors.of(context).border, height: 1),
      _navTile(
        icon: Icons.key_outlined,
        iconColor: AppColors.of(context).primary,
        title: l10n.mailAppPasswords,
        onTap: () => context.push('${RouteConstants.mail}/app-passwords'),
      ),
    ],
  ),
),
```

(Сверь фактические сигнатуры `_sectionHeader`/`_navTile`/`AppCard` в файле и повтори их.)

- [x] **Step 3:** `flutter analyze` чисто. Commit: `git add lib/ && git commit -m "feat(mail): app passwords screen + settings entry"`

---

### Task 7: Assistant tools (Flutter): schema + executor

**Files:**
- Modify: `lib/features/assistant/tools/assistant_tools_schema.dart`
- Modify: `lib/features/assistant/tools/assistant_tools_executor.dart`

- [x] **Step 1: Schema.** В список non-translator tools в `assistantToolSchemas()` добавить 4 схемы (flat realtime-формат, как соседние):

```dart
{
  'type': 'function',
  'name': 'check_mail',
  'description':
      'Check the user\'s @talerid.io mailbox: returns the latest inbox emails (from, subject, date, seen, uid). Call when user asks "проверь почту", "есть новые письма?", "check my mail".',
  'parameters': {
    'type': 'object',
    'properties': {
      'limit': {
        'type': 'integer',
        'description': 'How many latest emails to return (default 5, max 20)',
      },
    },
  },
},
{
  'type': 'function',
  'name': 'read_mail',
  'description':
      'Read one email by uid (from check_mail). Returns full text body. Call when user asks to read/open a specific email.',
  'parameters': {
    'type': 'object',
    'properties': {
      'uid': {'type': 'integer', 'description': 'Email uid from check_mail'},
    },
    'required': ['uid'],
  },
},
{
  'type': 'function',
  'name': 'send_mail',
  'description':
      'Send an email from the user\'s @talerid.io address. ALWAYS confirm recipient, subject and text with the user out loud BEFORE calling this tool.',
  'parameters': {
    'type': 'object',
    'properties': {
      'to': {'type': 'string', 'description': 'Recipient email address'},
      'subject': {'type': 'string', 'description': 'Email subject'},
      'text': {'type': 'string', 'description': 'Email body (plain text)'},
    },
    'required': ['to', 'subject', 'text'],
  },
},
{
  'type': 'function',
  'name': 'create_mail_app_password',
  'description':
      'Create an app password for connecting external mail clients (Apple Mail, Gmail app). The password value is NOT returned to you — tell the user to check the App Passwords screen in Settings. Just pass a label like "iPhone Apple Mail".',
  'parameters': {
    'type': 'object',
    'properties': {
      'label': {'type': 'string', 'description': 'Device/client label'},
    },
    'required': ['label'],
  },
},
```

- [x] **Step 2: Executor.** В `assistant_tools_executor.dart` добавить ветки перед финальным `else` (паттерн web_search — прямые вызовы `client` = DioClient):

```dart
} else if (name == 'check_mail') {
  final limit = ((args['limit'] as num?)?.toInt() ?? 5).clamp(1, 20);
  try {
    final data = await client.get<Map<String, dynamic>>(
      '/mail/messages',
      fromJson: (d) => Map<String, dynamic>.from(d as Map),
    );
    final items = (data['items'] as List? ?? [])
        .take(limit)
        .map((m) => {
              'uid': m['uid'],
              'from': m['from'],
              'subject': m['subject'],
              'date': m['date'],
              'seen': m['seen'],
              'snippet': m['snippet'],
            })
        .toList();
    output = jsonEncode({'emails': items, 'total_loaded': items.length});
  } catch (e) {
    output = jsonEncode({
      'error': e.toString().contains('404')
          ? 'no_mailbox_yet — suggest creating an address in Settings → Mail'
          : 'mail_unavailable',
    });
  }
} else if (name == 'read_mail') {
  final uid = (args['uid'] as num?)?.toInt();
  if (uid == null) {
    output = jsonEncode({'error': 'uid_required'});
  } else {
    final data = await client.get<Map<String, dynamic>>(
      '/mail/messages/$uid',
      fromJson: (d) => Map<String, dynamic>.from(d as Map),
    );
    output = jsonEncode({
      'from': data['from'],
      'to': data['to'],
      'subject': data['subject'],
      'date': data['date'],
      'text': (data['text'] as String? ?? '').length > 4000
          ? (data['text'] as String).substring(0, 4000)
          : data['text'],
      'attachments':
          (data['attachments'] as List? ?? []).map((a) => a['filename']).toList(),
    });
  }
} else if (name == 'send_mail') {
  final to = (args['to'] as String? ?? '').trim();
  final subject = args['subject'] as String? ?? '';
  final text = args['text'] as String? ?? '';
  if (to.isEmpty || text.isEmpty) {
    output = jsonEncode({'error': 'to_and_text_required'});
  } else {
    await client.post(
      '/mail/messages',
      data: {'to': to, 'subject': subject, 'text': text},
      fromJson: (d) => d,
    );
    output = jsonEncode({'ok': true, 'sent_to': to});
  }
} else if (name == 'create_mail_app_password') {
  final label = (args['label'] as String? ?? 'Mail client').trim();
  final data = await client.post<Map<String, dynamic>>(
    '/mail/app-passwords',
    data: {'label': label},
    fromJson: (d) => Map<String, dynamic>.from(d as Map),
  );
  // Пароль НЕ отдаём в LLM (не должен проговариваться вслух).
  output = jsonEncode({
    'ok': true,
    'label': data['label'],
    'note':
        'Password created. Tell the user to open Settings → Mail → App passwords to view it (it is NOT shown here for security).',
  });
}
```

⚠️ Секьюрити-инвариант: `create_mail_app_password` НЕ возвращает пароль в LLM-контекст. NB: бэкенд отдаёт password в ответе — executor его сознательно выбрасывает.

- [x] **Step 3:** `flutter analyze` чисто; если есть тесты executor'а (`grep -rl AssistantToolsExecutor test/`) — прогнать. Commit: `git add lib/features/assistant && git commit -m "feat(mail): assistant tools check_mail/read_mail/send_mail/create_mail_app_password"`

---

### Task 8: Backend — промпты ассистента + MCP mail tools

**Files (репо ~/Downloads/taler_id, ветка dev):**
- Modify: `src/assistant/prompts/ru.md`, `src/assistant/prompts/en.md`
- Create: `src/mcp/tools/mail.tools.ts`
- Modify: `src/mcp/mcp-server.factory.ts`, `src/mcp/mcp.module.ts`, файл scope-констант (`grep -rn "mcp:notes" src/mcp/` — фактическое имя)
- Test: `src/mcp/mcp-server.factory.spec.ts` (обновить ожидания)

- [x] **Step 1: Промпты.** В `ru.md` добавить секцию (в `en.md` — английский аналог):

```markdown
ПОЧТА (@talerid.io):
У пользователя есть личный почтовый ящик. Доступные tools:
- check_mail — последние письма из inbox (uid, отправитель, тема, дата). «Проверь почту», «есть новые письма?»
- read_mail — прочитать письмо по uid из check_mail. Перескажи содержимое кратко, если письмо длинное.
- send_mail — отправить письмо. ВСЕГДА проговори вслух получателя, тему и текст и дождись подтверждения пользователя ПЕРЕД вызовом.
- create_mail_app_password — создать пароль приложения для подключения внешних почтовых клиентов (Apple Mail и т.п.). Сам пароль тебе не показывается — скажи пользователю открыть Настройки → Почта → Пароли приложений.
Если tools возвращают no_mailbox_yet — предложи создать адрес в Настройках → Почта.
```

- [x] **Step 2: `src/mcp/tools/mail.tools.ts`** (паттерн messenger.tools.ts; `json`/`err` хелперы — скопируй импорт из соседнего файла):

```typescript
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { MailAccountService } from '../../mail/mail-account.service';
import type { MailBridgeService } from '../../mail/mail-bridge.service';

const json = (data: unknown) => ({
  content: [{ type: 'text' as const, text: JSON.stringify(data) }],
});
const err = (message: string) => ({
  content: [{ type: 'text' as const, text: JSON.stringify({ error: message }) }],
  isError: true,
});

export function registerMailReadTools(
  server: McpServer,
  bridge: MailBridgeService,
  userId: string,
) {
  server.tool(
    'check_mail',
    'Возвращает последние письма из почтового ящика пользователя @talerid.io (uid, from, subject, date, seen, snippet).',
    { limit: z.number().int().min(1).max(20).optional().describe('Сколько писем вернуть (default 5)') },
    async ({ limit }) => {
      try {
        const page = await bridge.listMessages(userId, 'INBOX', undefined, limit ?? 5);
        return json(page.items);
      } catch (e) {
        return err((e as Error).message.includes('mail_account')
          ? 'no_mailbox_yet'
          : 'mail_unavailable');
      }
    },
  );

  server.tool(
    'read_mail',
    'Читает письмо по uid (из check_mail). Возвращает текст письма.',
    { uid: z.number().int().describe('uid письма из check_mail') },
    async ({ uid }) => {
      const msg = await bridge.getMessage(userId, uid);
      return json({
        from: msg.from, to: msg.to, subject: msg.subject, date: msg.date,
        text: msg.text.slice(0, 4000),
        attachments: msg.attachments.map((a) => a.filename),
      });
    },
  );
}

export function registerMailSendTool(
  server: McpServer,
  bridge: MailBridgeService,
  userId: string,
) {
  server.tool(
    'send_mail',
    'Отправляет письмо от имени пользователя с его адреса @talerid.io. Подтверди у пользователя получателя и текст перед вызовом.',
    {
      to: z.string().email().describe('Email получателя'),
      subject: z.string().max(255).describe('Тема'),
      text: z.string().min(1).describe('Текст письма'),
    },
    async ({ to, subject, text }) => {
      await bridge.sendMessage(userId, { to, subject, text });
      return json({ ok: true, sent_to: to });
    },
  );
}
```

(`create_mail_app_password` в MCP сознательно НЕ добавляем — внешним MCP-клиентам создавать IMAP-креды не даём; он только в in-app ассистенте.)

- [x] **Step 3: Wiring.** В scope-константы добавить `'mcp:mail.read'`, `'mcp:mail.send'` (по образцу messages.read/send). В `McpServerFactory`: инжект `MailBridgeService`, в `buildServer`:

```typescript
if (scopes.includes('mcp:mail.read')) {
  registerMailReadTools(server, this.mailBridge, userId);
}
if (scopes.includes('mcp:mail.send')) {
  registerMailSendTool(server, this.mailBridge, userId);
}
```

В `mcp.module.ts` imports добавить `MailModule` (он экспортирует MailBridgeService — проверь exports в `src/mail/mail.module.ts`, при необходимости добавь).

- [x] **Step 4: Обновить `mcp-server.factory.spec.ts`** — добавить кейс:

```typescript
it('mail scopes → mail tools', () => {
  expect(toolNames(['mcp:mail.read', 'mcp:mail.send'])).toEqual([
    'check_mail', 'read_mail', 'send_mail',
  ]);
});
```

и поправить существующий «all scopes» кейс (+3 tools). Прогнать: `npx jest src/mcp/ src/assistant/` → зелёные.

- [x] **Step 5: Commit** — `git add src/ && git commit -m "feat(mail): assistant prompts + MCP mail tools"`

---

### Task 9: Integration test + полный прогон

**Files:**
- Modify: `integration_test/app_test.dart` (mobile)

- [ ] **Step 1:** Добавить шаг «Почта» после шага Settings (вход через Settings, mail НЕ в орбите — точку входа орбитального экрана не менять!):

```dart
// Mail (via Settings)
await tester.openTab(Icons.settings_outlined);
await tester.pumpFor(const Duration(seconds: 2));
final mailTile = find.text('Почта').first;
if (await tester.safeTap(mailTile)) {
  await tester.pumpFor(const Duration(seconds: 3));
  expect(find.byType(ErrorWidget), findsNothing,
      reason: 'Mail inbox should not crash');
  debugPrint('[TEST] ✓ Mail inbox OK');
  // назад в settings
  if (find.byIcon(Icons.arrow_back).evaluate().isNotEmpty) {
    await tester.tap(find.byIcon(Icons.arrow_back).first, warnIfMissed: false);
    await tester.pumpFor(const Duration(seconds: 1));
  }
}
await tester.goHome();
```

(Текст 'Почта' — т.к. интеграционный тест гоняется с ru-локалью; сверь, как другие шаги находят пункты Settings, и повтори их подход.)

- [ ] **Step 2: Полный прогон Flutter-тестов** — `flutter test` → все зелёные (юнит + mail).

- [ ] **Step 3: Интеграционный тест на эмуляторе** (по CLAUDE.md): запустить `Pixel_XL_API_33`, `flutter test integration_test/app_test.dart --flavor dev --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol -d emulator-5554`. Из-за гейта выбора адреса тестовый аккаунт `integration_test@taler-test.com` УЖЕ имеет ящик (`inttest1`) → гейт не сработает; если тест упрётся в MailAddressSetupScreen — проверить логику `hasMailbox`.

- [ ] **Step 4: Commit + push** — `git add integration_test && git commit -m "test(mail): integration step for mail screens" && git push origin dev`. Backend: `cd ~/Downloads/taler_id && git push origin dev` + деплой DEV (`ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev'`) + `npm run test:mail` (19/19) для регрессии.

---

### Task 10: Ручная проверка на устройстве (гейт перед релизом)

- [ ] **Step 1:** dev-APK или `flutter run --flavor dev` на устройстве: регистрация нового тестового юзера → после онбординга появляется экран выбора адреса → занятый/зарезервированный/невалидный localpart показывают ошибки → создание успешно.
- [ ] **Step 2:** Настройки → Почта: inbox грузится, письмо открывается (HTML и plain), reply/compose/вложение работают, swipe-delete работает.
- [ ] **Step 3:** App-пароль: создать → скопировать → подключить Apple Mail/K-9 по инструкции с экрана → почта ходит; отозвать → клиент отваливается (≤1 мин).
- [ ] **Step 4:** Ассистент голосом: «проверь почту» → называет письма; «прочитай последнее» → читает; «отправь письмо на <адрес>» → подтверждает и шлёт; «создай пароль приложения» → создаёт и отправляет в Настройки.
- [ ] **Step 5:** Кнопка «Позже» на экране выбора адреса: не показывается повторно при следующем логине; вход в Почту из Настроек предлагает создать адрес.

## Вне scope Phase 2 (бэклог)
Push о новых письмах, папки/поиск/threading, платные квоты, per-tenant домены, suspend при удалении юзера (+reconcile-скрипт), кэш inbox офлайн.

## Self-review notes
- Spec coverage: онбординг-шаг (T4), экран старых юзеров = тот же гейт `noAccount`/CTA (T4+T5), минимальный клиент inbox/чтение/compose/reply/вложения (T5), app-пароли+инструкция (T6), Settings-вход (T6), assistant-first (T7 client + T8 prompts/MCP), локализация (T3), тесты (T2, T9), деплой-регрессия (T9).
- Расхождение со спекой: вход «с экрана профиля» — опущен (вход из Settings достаточен для Phase 2; орбиту не трогаем по феедбеку). Отмечено сознательно.
- Типы согласованы: IMailRepository сигнатуры в T1 = использование в T2/T4/T5/T6; RouteConstants.mail/mailAddressSetup в T3 = T4/T5/T6.
- Известные точки сверки с реальностью (в шагах): методы DioClient (getBytes/delete), сигнатуры _navTile/AppCard, имена scope-констант MCP, наличие path_provider в pubspec (есть почти наверняка — используется повсеместно; если нет, добавить).


