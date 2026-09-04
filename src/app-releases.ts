export interface AppRelease {
  version: string;
  build: number;
  date: string;
  flavor: string;
  notes_ru: string;
  notes_en: string;
}

// Append entries on top whenever a new version ships.
// Keep notes user-facing (no internal jargon, no commit hashes).
export const APP_RELEASES: AppRelease[] = [
  {
    version: '1.1.28',
    build: 229,
    date: '2026-09-04',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.28 — чат в комнате звонка.\n\n' +
      '💬 В звонке появился текстовый чат: можно писать друг другу, не прерывая ' +
      'разговор. Удобно для ссылок, адресов, номеров, кодов и сумм — того, что ' +
      'проще написать, чем продиктовать.\n\n' +
      '🌐 Чат общий для всех участников: он работает между приложением на телефоне, ' +
      'десктопом и теми, кто зашёл в комнату из браузера по ссылке.\n\n' +
      '🤖 Ассистенту можно сказать «напиши в чат» — он отправит сообщение сам, ' +
      'не отвлекая вас от разговора.\n\n' +
      '🔔 Непрочитанные сообщения отмечаются значком на кнопке чата.\n\n' +
      'Чат живёт только во время звонка: вошедший позже не увидит написанного до ' +
      'него, а после завершения переписка не сохраняется.',
    notes_en:
      'Release 1.1.28 — chat inside the call room.\n\n' +
      '💬 Calls now have a text chat, so you can write to each other without ' +
      'interrupting the conversation. Handy for links, addresses, numbers, codes ' +
      'and amounts — anything easier to type than to say out loud.\n\n' +
      '🌐 The chat is shared by everyone in the room: it works between the phone ' +
      'app, the desktop app and guests who joined from a browser link.\n\n' +
      '🤖 You can tell the assistant to write something in the chat and it will ' +
      'send the message for you, without pulling you out of the call.\n\n' +
      '🔔 Unread messages are marked with a badge on the chat button.\n\n' +
      'The chat lives only for the duration of the call: whoever joins later will ' +
      'not see earlier messages, and nothing is kept after the call ends.',
  },
  {
    version: '1.1.27',
    build: 228,
    date: '2026-08-28',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.27 — громкая связь в звонках на Android.\n\n' +
      '🔊 Кнопка «Динамик» наконец работает. Раньше на Android приложение ' +
      'включало громкую связь и тут же само её выключало — звук так и оставался ' +
      'в разговорном динамике. Теперь выбранный вывод сохраняется до конца ' +
      'разговора.\n\n' +
      '📞 Возврат после чужого звонка. Если во время разговора приходил ' +
      'телефонный вызов или срабатывал будильник, после него звук больше не ' +
      'сбрасывается обратно в трубку.\n\n' +
      '🎧 Bluetooth-гарнитура. Её отключение больше не уводит звук с громкой ' +
      'связи, если вы включили её осознанно.\n\n' +
      'На iOS вывод звука работал корректно и не менялся.',
    notes_en:
      'Release 1.1.27 — speakerphone in calls on Android.\n\n' +
      '🔊 The Speaker button finally works. On Android the app used to switch ' +
      'the loudspeaker on and immediately back off, leaving the call on the ' +
      'earpiece. The output you pick now sticks for the whole call.\n\n' +
      '📞 Coming back from an interruption. After an incoming phone call or an ' +
      'alarm, the call no longer drops back to the earpiece.\n\n' +
      '🎧 Bluetooth headsets. Unplugging one no longer yanks the call off the ' +
      'loudspeaker you deliberately turned on.\n\n' +
      'iOS audio routing was already correct and is unchanged.',
  },
  {
    version: '1.1.26',
    build: 227,
    date: '2026-08-11',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.26 — переписка стала удобнее.\n\n' +
      '↩️ Настоящие ответы. Ответ больше не вклеивается в текст: цитата стоит ' +
      'отдельной строкой, по ней можно перейти к исходному сообщению, а если его ' +
      'удалили — так и написано.\n\n' +
      '📤 Пересылка с подписью. У пересланного видно, от кого оно пришло. ' +
      'Пересылать можно сразу несколько.\n\n' +
      '✅ Выделение нескольких. Долгий тап — «Выделить», дальше отмечайте ' +
      'сообщения и удаляйте, пересылайте или копируйте их пачкой.\n\n' +
      '🆕 Линия непрочитанных. Чат открывается на первом непрочитанном ' +
      'сообщении, а не в самом низу.\n\n' +
      '💬 Черновики и порядок чатов — на всех устройствах. Недописанное ' +
      'сообщение, архив и закреплённые чаты теперь одинаковы на телефоне и ' +
      'компьютере.\n\n' +
      '@ Упоминания. Наберите @ — появятся подсказки участников. Если упомянули ' +
      'вас, рядом с чатом загорится значок, и уведомление придёт даже когда чат ' +
      'приглушён.\n\n' +
      '🔗 Превью ссылок. Под сообщением со ссылкой появляется карточка с ' +
      'заголовком и картинкой.\n\n' +
      '🎤 Голосовые. Дорожка теперь повторяет громкость записи, а под сообщением ' +
      'есть «Расшифровать» — голосовое можно прочитать текстом.\n\n' +
      '🎟 Приглашения в группы и каналы. Ссылку можно создать, отправить и ' +
      'отозвать; у канала может быть короткое публичное имя.\n\n' +
      '👁 Просмотры. У постов канала видно, сколько человек их прочитало.\n\n' +
      '✍️ Форматирование и спойлеры. **жирный**, __курсив__, ~~зачёркнутый~~, ' +
      '`код` и ||скрытый текст||, который открывается по нажатию.\n\n' +
      '⏰ Отправка позже и без звука. Долгий тап по кнопке отправки — выбрать ' +
      'время или отправить так, чтобы не разбудить уведомлением.',
    notes_en:
      'Release 1.1.26 — a friendlier chat.\n\n' +
      '↩️ Real replies. A reply is no longer glued into the text: the quote sits ' +
      'on its own line, tapping it jumps to the original, and if the original was ' +
      'deleted it says so.\n\n' +
      '📤 Forwarding with attribution. Forwarded messages show who wrote them, ' +
      'and you can forward several at once.\n\n' +
      '✅ Multi-select. Long-press, choose Select, then delete, forward or copy ' +
      'messages in bulk.\n\n' +
      '🆕 Unread divider. A chat opens at the first unread message instead of the ' +
      'very bottom.\n\n' +
      '💬 Drafts and chat order everywhere. Unfinished messages, the archive and ' +
      'pinned chats are now the same on your phone and computer.\n\n' +
      '@ Mentions. Type @ to get suggestions. If someone mentions you, the chat ' +
      'gets a badge and the notification arrives even when the chat is muted.\n\n' +
      '🔗 Link previews. A card with the title and image appears under a message ' +
      'with a link.\n\n' +
      '🎤 Voice messages. The waveform now follows the actual recording, and ' +
      'Transcribe turns a voice message into text.\n\n' +
      '🎟 Invite links. Create, share and revoke links to groups and channels; a ' +
      'channel can have a short public handle.\n\n' +
      '👁 Views. Channel posts show how many people have read them.\n\n' +
      '✍️ Formatting and spoilers. **bold**, __italic__, ~~strikethrough~~, ' +
      '`code` and ||hidden text|| that reveals on tap.\n\n' +
      '⏰ Send later and silently. Long-press the send button to pick a time or ' +
      'send without a notification sound.',
  },
  {
    version: '1.1.25',
    build: 226,
    date: '2026-08-08',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.25 — закреплённые сообщения.\n\n' +
      '📌 Закрепление сообщений. Важное сообщение можно закрепить, и оно ' +
      'останется на виду в шапке чата — в личной переписке, в группе и в канале. ' +
      'Закрепить можно несколько: плашка показывает, сколько их, а по нажатию ' +
      'листает и переносит к нужному сообщению.\n\n' +
      '📋 Список закреплённых. Отдельный экран со всеми закреплёнными ' +
      'сообщениями чата: оттуда можно перейти к любому, снять закрепление с ' +
      'одного или убрать все сразу.\n\n' +
      '🙈 Плашку можно свернуть. Если закреплённое вам сейчас не нужно, ' +
      'нажмите крестик — плашка скроется только у вас и вернётся, когда ' +
      'закрепят что-то новое.\n\n' +
      '🎙 Голосом. Ассистента можно попросить закрепить или открепить ' +
      'сообщение и рассказать, что закреплено в чате.\n\n' +
      'В личной переписке закрепить может любой участник, в группах и каналах — ' +
      'владелец и администраторы.',
    notes_en:
      'Release 1.1.25 — pinned messages.\n\n' +
      '📌 Pin a message. Anything important can be pinned and stays visible at ' +
      'the top of the chat — in direct messages, groups and channels. Pin ' +
      'several: the bar shows how many there are, and tapping it cycles through ' +
      'them and jumps to each message.\n\n' +
      '📋 Pinned list. A separate screen with every pinned message in the chat: ' +
      'jump to any of them, unpin one, or clear them all at once.\n\n' +
      '🙈 Hide the bar. If you do not need the pinned message right now, tap the ' +
      'cross — it hides for you only, and comes back when something new is ' +
      'pinned.\n\n' +
      '🎙 By voice. Ask the assistant to pin or unpin a message, or to tell you ' +
      'what is pinned in a chat.\n\n' +
      'In direct messages anyone can pin; in groups and channels the owner and ' +
      'admins can.',
  },
  {
    version: '1.1.24',
    build: 225,
    date: '2026-08-04',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.24 — вход с нового устройства под вашим контролем, и снова ' +
      'работающий вход через Taler ID на сторонних сайтах.\n\n' +
      '🔐 Доверенные устройства. Теперь вход в аккаунт с незнакомого устройства ' +
      'можно потребовать подтверждать: на доверенное устройство приходит ' +
      'уведомление, и вы разрешаете или отклоняете вход одним касанием, а новое ' +
      'устройство ждёт решения на отдельном экране. Список доверенных устройств ' +
      'и сам переключатель — в настройках.\n\n' +
      '🔗 Вход через Taler ID на стороннем сайте. Ссылку могла перехватить не та ' +
      'сборка приложения — тестовая вместо основной, — и вход обрывался ошибкой. ' +
      'Теперь каждая сборка отвечает только за свои адреса.\n\n' +
      '🔑 Вход по коду из приложения-аутентификатора снова работает.\n\n' +
      '📅 Календарь: удалённые события больше не возвращаются после обновления, ' +
      'а нажатие на задачу открывает её карточку.\n\n' +
      '⚠️ Если запрос всё же не прошёл, приложение показывает настоящую причину, ' +
      'а не «Internal server error».',
    notes_en:
      'Release 1.1.24 — new-device sign-in under your control, and signing in with ' +
      'Taler ID on partner sites working again.\n\n' +
      '🔐 Trusted devices. A sign-in from an unfamiliar device can now require your ' +
      'approval: a notification reaches a device you trust, you allow or reject it ' +
      'with one tap, and the new device waits on a screen of its own. The list of ' +
      'trusted devices and the toggle itself live in settings.\n\n' +
      '🔗 Signing in with Taler ID on a partner site. The link could be picked up by ' +
      'the wrong build of the app — the test one instead of the main one — and the ' +
      'sign-in died with an error. Each build now answers only for its own addresses.\n\n' +
      '🔑 Signing in with a code from your authenticator app works again.\n\n' +
      '📅 Calendar: deleted events no longer come back after a refresh, and tapping a ' +
      'task opens its detail.\n\n' +
      '⚠️ When a request does fail, the app shows the real reason instead of ' +
      '"Internal server error".',
  },
  {
    version: '1.1.23',
    build: 224,
    date: '2026-08-03',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.23 — ссылки открываются в приложении, и связь там, где её резали.\n\n' +
      '⚠️ Если у вас 1.1.22 — обновитесь: в ней ссылки перехватывались приложением ' +
      'и упирались в пустой экран.\n\n' +
      '🔗 Приглашение в комнату и вход через Taler ID на стороннем сайте теперь ' +
      'открывают экран подтверждения внутри приложения, а после согласия возвращают ' +
      'на сайт уже с выполненным входом. Раньше это не работало ни разу: ссылку ' +
      'принимал системный слой, а в приложении её никто не обрабатывал.\n\n' +
      '🌐 Связь без VPN: если провайдер режет доступ к нашим серверам, приложение ' +
      'снова само переключается на запасной канал. Звонки при этом идут только по ' +
      'тем каналам, где они действительно работают.\n\n' +
      '🔔 Наличие новой версии проверяется при каждом запуске и при возвращении из ' +
      'фона. Раньше запуск по входящему звонку пропускал и эту проверку, и ' +
      'подключение к серверу сообщений.',
    notes_en:
      'Release 1.1.23 — links open in the app, and connectivity where it was blocked.\n\n' +
      '⚠️ On 1.1.22? Update: there, links were claimed by the app and led to a blank ' +
      'screen.\n\n' +
      '🔗 Room invites and signing in with Taler ID on a partner site now open the ' +
      'consent screen inside the app, and hand you back to the site signed in. This ' +
      'never once worked before: the system delivered the link and nothing in the app ' +
      'was listening for it.\n\n' +
      '🌐 Connectivity without a VPN: where an ISP blocks our servers, the app falls ' +
      'back to a working route again. Calls only ever travel routes that can carry them.\n\n' +
      '🔔 The version check runs on every launch and on returning from the background. ' +
      'A launch from an incoming call used to skip both it and the message-server ' +
      'connection.',
  },
  {
    version: '1.1.22',
    build: 223,
    date: '2026-08-03',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.22 — задачи в календаре и ссылки, открывающиеся в приложении.\n\n' +
      '✅ Задачи: теперь в календаре можно создавать не только события, но и задачи. ' +
      'Задача помечается выполненной одним касанием и выглядит иначе, чем событие.\n\n' +
      '🗑️ Кнопки «выполнить» и «удалить» стали видимыми — раньше на компьютере до них ' +
      'было не добраться.\n\n' +
      '🔗 Ссылки открываются в приложении, а не в браузере: приглашение в комнату, ' +
      'приглашение в организацию и вход через Taler ID на стороннем сайте. ' +
      'Раньше это работало только на части адресов, а на talerid.io — не работало вовсе.\n\n' +
      '🔐 Вход через Taler ID на сайтах-партнёрах: страница подтверждения довела бы ' +
      'до конца не каждый вход — кнопка «Разрешить» могла молча ничего не делать. Исправлено.',
    notes_en:
      'Release 1.1.22 — calendar tasks, and links that open in the app.\n\n' +
      '✅ Tasks: the calendar now holds tasks as well as events. A task is completed with ' +
      'a single tap and looks distinct from an event.\n\n' +
      '🗑️ Complete and delete buttons are now visible — on desktop they were out of reach.\n\n' +
      '🔗 Links open in the app instead of the browser: room invites, organisation invites, ' +
      'and signing in with Taler ID on a partner site. This only ever worked on some ' +
      'addresses, and never on talerid.io.\n\n' +
      '🔐 Signing in with Taler ID on partner sites: the consent page did not always finish ' +
      'the flow — "Allow" could silently do nothing. Fixed.',
  },
  {
    version: '1.1.21',
    build: 222,
    date: '2026-07-30',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.21 — звонки и защита приложения.\n\n' +
      '📞 Исправлено: звонивший мог не слышать собеседника, хотя тот отвечал. ' +
      'Проблема была на стороне звонящего — приложение принимало сигнал «вам ответили» ' +
      'за «ответили с другого устройства» и глушило собственный звук.\n\n' +
      '🔕 Больше не звонит «из прошлого»: входящий вызов, пришедший пока телефон был ' +
      'офлайн, теперь не всплывает при возвращении в сеть.\n\n' +
      '🎙️ Ассистент в звонке: при сворачивании экрана микрофон возвращается собеседнику, ' +
      'а не остаётся выключенным до конца разговора.\n\n' +
      '☎️ Две линии: «Завершить этот звонок» больше не обрывает вторую линию.\n\n' +
      '🔐 PIN-код: попытки ввода теперь считаются между запусками приложения, ' +
      'а сам код хранится надёжнее. Отключить PIN можно только в настройках — ' +
      'ассистент этого больше не делает.\n\n' +
      '🛡️ Данные приложения (ключи, документы) больше не попадают в резервные копии Android.',
    notes_en:
      'Release 1.1.21 — calls and app protection.\n\n' +
      '📞 Fixed: the caller could hear nothing even though the other side had answered. ' +
      'The bug was on the caller\'s device — it read "your call was answered" as ' +
      '"answered on another device" and tore down its own audio.\n\n' +
      '🔕 No more calls from the past: an incoming call that arrived while the phone was ' +
      'offline no longer pops up when you come back online.\n\n' +
      '🎙️ In-call assistant: minimising the screen now hands the microphone back to the ' +
      'call instead of leaving it muted for the rest of it.\n\n' +
      '☎️ Two lines: "End this call" no longer drops the second line as well.\n\n' +
      '🔐 PIN: failed attempts now persist across app restarts and the code itself is ' +
      'stored more securely. Turning the PIN off happens in Settings only — the ' +
      'assistant can no longer do it.\n\n' +
      '🛡️ App data (keys, documents) is excluded from Android backups.',
  },
  {
    version: '1.1.20',
    build: 219,
    date: '2026-07-24',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.20 — папки в почте.\n\n' +
      '📁 Папки: Входящие, Отправленные, Черновики, Спам и Корзина — плюс свои папки.\n\n' +
      '📤 Отправленные письма теперь сохраняются в «Отправленные».\n\n' +
      '📝 Черновики: недописанное письмо можно сохранить и вернуться к нему позже.\n\n' +
      '🗑️ Удалённые письма попадают в Корзину, а не исчезают безвозвратно.\n\n' +
      '🔔 На планете «Почта» появился счётчик непрочитанных писем.\n\n' +
      '📰 Канал новостей теперь корректно подписан «Taler ID».',
    notes_en:
      'Release 1.1.20 — mail folders.\n\n' +
      '📁 Folders: Inbox, Sent, Drafts, Spam and Trash — plus your own folders.\n\n' +
      '📤 Sent messages are now saved to Sent.\n\n' +
      '📝 Drafts: save an unfinished email and come back to it later.\n\n' +
      '🗑️ Deleted messages go to Trash instead of disappearing forever.\n\n' +
      '🔔 The Mail planet now shows an unread counter.\n\n' +
      '📰 The news channel is now correctly signed «Taler ID».',
  },
  {
    version: '1.1.19',
    build: 218,
    date: '2026-07-24',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.19 — собственная почта.\n\n' +
      '📧 У каждого пользователя теперь может быть свой почтовый адрес: выберите имя ящика — и получайте и отправляйте письма прямо из приложения.\n\n' +
      '📬 Раздел «Почта»: входящие, чтение писем, ответы, вложения.\n\n' +
      '🔑 Пароли приложений: подключите ящик в привычном почтовом клиенте (Apple Mail, Outlook и др.).\n\n' +
      '🗣️ Ассистент умеет проверять почту, читать письма вслух и отправлять их голосовой командой.\n\n' +
      '📰 Новый системный канал «Taler ID — Новости» с новостями о релизах.',
    notes_en:
      'Release 1.1.19 — your own mailbox.\n\n' +
      '📧 Every user can now have a personal email address: pick a mailbox name and send/receive mail right in the app.\n\n' +
      '📬 Mail section: inbox, reading, replies, attachments.\n\n' +
      '🔑 App passwords: connect your mailbox in a regular mail client (Apple Mail, Outlook, etc.).\n\n' +
      '🗣️ The assistant can check mail, read messages aloud and send email by voice.\n\n' +
      '📰 New “Taler ID — News” system channel with release news.',
  },
  {
    version: '1.1.18',
    build: 217,
    date: '2026-07-24',
    flavor: 'dev',
    notes_ru:
      'Сборка 217 — почта @talerid.io, доработки по отзывам.\n\n' +
      '📧 Письма теперь открываются на светлом фоне — как в привычных почтовых приложениях.\n\n' +
      '✉️ Исправлено оформление экрана ответа: подписи полей «Кому» и «Тема» больше не обрезаются.\n\n' +
      '📬 Список писем стал чище: убраны разделительные линии, предпросмотр показывает текст письма без служебных символов.',
    notes_en:
      'Build 217 — @talerid.io mail, feedback fixes.\n\n' +
      '📧 Emails now open on a light background — like in familiar mail apps.\n\n' +
      '✉️ Fixed the reply screen layout: the To and Subject field labels are no longer clipped.\n\n' +
      '📬 A cleaner message list: divider lines removed, previews show the message text without technical artifacts.',
  },
  {
    version: '1.1.18',
    build: 216,
    date: '2026-07-19',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.18 — стабильность звонков.\n\n' +
      '📞 Исправлена редкая гонка при звонке на несколько устройств одновременно: звук больше не пропадает, когда отвечают с другого устройства.\n\n' +
      '🔍 Добавлена диагностика аудио-подключений для более быстрого разбора проблем со звуком.',
    notes_en:
      'Release 1.1.18 — call stability.\n\n' +
      '📞 Fixed a rare race when calling multiple devices at once: audio no longer drops when the call is answered on another device.\n\n' +
      '🔍 Added audio-connection diagnostics for faster troubleshooting of sound issues.',
  },
  {
    version: '1.1.17',
    build: 215,
    date: '2026-07-18',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.17 — ассистент стал обновляемым на лету.\n\n' +
      '⚡ Инструкции ассистента теперь загружаются с сервера: улучшения его поведения будут приходить мгновенно, без обновления приложения.\n\n' +
      '📴 Без интернета ассистент работает как раньше — встроенные инструкции остаются запасным вариантом.',
    notes_en:
      'Release 1.1.17 — the assistant now updates on the fly.\n\n' +
      '⚡ Assistant instructions are now loaded from the server: behavior improvements arrive instantly, without an app update.\n\n' +
      '📴 Offline the assistant works as before — built-in instructions remain as a fallback.',
  },
  {
    version: '1.1.16',
    build: 214,
    date: '2026-07-18',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.16 — точечные исправления ассистента.\n\n' +
      '🔇 Ассистент больше не «комментирует со стороны» ваши же реплики — убрано эхо собственной истории в голосовой сессии.\n\n' +
      '🎯 Поручения «найди билеты/отель/вариант» надёжно уходят AI-аналитику, в том числе повторно после уточнений — ассистент не скажет «передал», не передав на самом деле.',
    notes_en:
      'Release 1.1.16 — targeted assistant fixes.\n\n' +
      '🔇 The assistant no longer "narrates" your own words — own-history echo is filtered out of the voice session.\n\n' +
      '🎯 Errands like "find tickets/a hotel" reliably reach the AI Analyst, including re-submission after clarifications — the assistant won\'t claim "sent" without actually sending.',
  },
  {
    version: '1.1.15',
    build: 213,
    date: '2026-07-18',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.15 — ассистент в привычном виде, чат внутри.\n\n' +
      '🪐 Вернули главный экран с «планетами»-разделами вокруг значка TalerID — как раньше.\n\n' +
      '💬 Чат с историей теперь внутри голосового окна ассистента: нажмите на центр — и вся история общения, живые реплики, текстовый ввод и файлы в одном месте.\n\n' +
      '🔗 Ссылки из веб-поиска ассистента кликабельны: попросили найти билеты — переходите на сайт прямо из чата.\n\n' +
      '🧭 Все пузыри-действия (встречи, сообщения, звонки, ответы аналитика) — в этой же ленте.',
    notes_en:
      'Release 1.1.15 — the assistant back to its classic look, chat inside.\n\n' +
      '🪐 The home screen with section "planets" orbiting the TalerID logo is back — just like before.\n\n' +
      '💬 The chat with history now lives inside the assistant voice window: tap the center — full conversation history, live replies, text input and files in one place.\n\n' +
      '🔗 Links from the assistant\'s web search are tappable: asked to find tickets — open the site right from the chat.\n\n' +
      '🧭 All action bubbles (events, messages, calls, analyst replies) live in the same feed.',
  },
  {
    version: '1.1.14',
    build: 212,
    date: '2026-07-18',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.14 — большой апдейт AI-ассистента.\n\n' +
      '💬 У ассистента появился полноценный чат: вся история общения (голосом и текстом) сохраняется и доступна с любого вашего устройства.\n\n' +
      '⌨️ Ассистенту теперь можно писать текстом — все команды работают как голосом: отправить сообщение, создать встречу, позвонить и т.д.\n\n' +
      '🔗 Действия ассистента — кликабельные: создал встречу — нажмите и откроется календарь; отправил сообщение — перейдёте прямо к нему.\n\n' +
      '📎 Ассистенту можно отправлять файлы (фото, PDF) — при необходимости он сам передаст их AI-аналитику и покажет ответ в чате.\n\n' +
      '📝 Недописанное сообщение ассистенту сохраняется как черновик — даже после перезапуска приложения.\n\n' +
      '🔊 Голос ассистента стал заметно громче.\n\n' +
      '🧭 Быстрые переходы в разделы — теперь прямо над чатом ассистента.',
    notes_en:
      'Release 1.1.14 — a major AI assistant update.\n\n' +
      '💬 The assistant now has a full chat: your entire conversation history (voice and text) is saved and available on all your devices.\n\n' +
      '⌨️ You can now type to the assistant — every command works the same as by voice: send a message, create an event, make a call, and more.\n\n' +
      '🔗 Assistant actions are tappable: created an event — tap to open the calendar; sent a message — jump right to it.\n\n' +
      '📎 Send files (photos, PDF) to the assistant — it will pass them to the AI analyst when needed and show the reply in the chat.\n\n' +
      '📝 An unsent message to the assistant is kept as a draft — even after restarting the app.\n\n' +
      '🔊 The assistant\'s voice is noticeably louder.\n\n' +
      '🧭 Quick section shortcuts now live right above the assistant chat.',
  },
  {
    version: '1.1.13',
    build: 211,
    date: '2026-07-17',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.13 — мессенджер, заметки и звонки.\n\n' +
      '✅ Статусы прочтения в группах — теперь галочками, как в личных чатах: одна — доставлено, две — прочитано. Кто именно прочитал — по долгому нажатию на сообщение.\n\n' +
      '👻 Починили «сообщения-призраки»: старые сообщения больше не приходят повторно.\n\n' +
      '📝 Заметки удаляются с первого раза и больше не возвращаются после обновления списка.\n\n' +
      '💾 На компьютере (macOS/Windows/Linux) вложения из чата теперь сохраняются через системный диалог «Сохранить как».\n\n' +
      '🌍 Синхронный перевод стало лучше слышно: голос собеседника приглушается сильнее, голос переводчика — громче.\n\n' +
      '📞 iPhone: параллельный входящий звонок WhatsApp больше не ломает разговор — звук автоматически восстанавливается.',
    notes_en:
      'Release 1.1.13 — messenger, notes and calls.\n\n' +
      '✅ Group read receipts are now ticks, like in direct chats: one tick — delivered, two — read. Long-press a message to see who read it.\n\n' +
      '👻 Fixed "ghost messages": old messages no longer arrive again.\n\n' +
      '📝 Notes now delete on the first try and stay deleted after refreshing.\n\n' +
      '💾 On desktop (macOS/Windows/Linux) chat attachments now save via the system "Save as" dialog.\n\n' +
      '🌍 Live translation is easier to hear: the peer\'s voice is ducked further and the translator voice is louder.\n\n' +
      '📞 iPhone: a parallel incoming WhatsApp call no longer breaks the conversation — audio recovers automatically.',
  },
  {
    version: '1.1.12',
    build: 210,
    date: '2026-07-13',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.12 — надёжность звонков.\n\n' +
      '🔇 Односторонняя тишина побеждена: если раньше в звонке собеседник вас слышал, а вы его нет (и помогал только перезвон) — теперь приложение само замечает «мёртвый» входящий аудиопоток по счётчикам трафика и восстанавливает его за 10-20 секунд без переподключения.\n\n' +
      '🌐 Звонки по ссылке из браузера (включая Telegram на iPhone): экран больше не гаснет во время звонка, а если телефон всё же заблокировали — звук автоматически возвращается после разблокировки.',
    notes_en:
      'Release 1.1.12 — call reliability.\n\n' +
      '🔇 One-way silence defeated: when the peer could hear you but you heard nothing (and only re-calling helped) — the app now detects a dead incoming audio stream via traffic counters and recovers it within 10-20 seconds, no reconnect needed.\n\n' +
      '🌐 Browser link calls (including Telegram on iPhone): the screen no longer sleeps during a call, and if the phone does get locked, audio recovers automatically after unlock.',
  },
  {
    version: '1.1.11',
    build: 209,
    date: '2026-07-12',
    flavor: 'both',
    notes_ru:
      'Мелкие улучшения статусов прочтения в мессенджере.\n\n' +
      '✅ В группах у вашего сообщения теперь всегда есть отметка статуса: галочка «отправлено», затем «прочитали N» по мере того как участники читают.\n\n' +
      'ℹ️ Подписи статусов прочтения и панель «кто прочитал + реакции» переведены на русский.',
    notes_en:
      'Read-receipt polish in the messenger.\n\n' +
      '✅ In groups your own message now always shows a status: a "sent" tick, then "Seen by N" as members read it.\n\n' +
      'ℹ️ Read-status labels and the "who read it + reactions" panel are now localized.',
  },
  {
    version: '1.1.10',
    build: 208,
    date: '2026-07-12',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.10 — статусы прочтения в мессенджере (как в Telegram).\n\n' +
      '✅ Галочки: ✓ отправлено, ✓✓ прочитано. В группах — «прочитали N», нажмите чтобы увидеть кто именно.\n\n' +
      'ℹ️ Долгое нажатие на своё сообщение открывает панель «кто прочитал + реакции».\n\n' +
      '🔕 Уведомление о сообщении теперь исчезает, когда вы прочитали чат — в том числе на других ваших устройствах (прочитали на компьютере — баннер на телефоне пропадает).\n\n' +
      '🔢 Точные счётчики непрочитанного и бейдж на иконке, синхронизированные между устройствами.',
    notes_en:
      'Release 1.1.10 — Telegram-style read receipts in the messenger.\n\n' +
      '✅ Ticks: ✓ sent, ✓✓ read. In groups — "Seen by N", tap to see exactly who.\n\n' +
      'ℹ️ Long-press your own message for a "read by + reactions" panel.\n\n' +
      '🔕 A message notification now clears when you read the chat — including on your other devices (read on desktop → the phone banner disappears).\n\n' +
      '🔢 Accurate per-chat unread counts and app-icon badge, synced across devices.',
  },
  {
    version: '1.1.9',
    build: 207,
    date: '2026-07-10',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.9 — доработки голосового ассистента и звонков.\n\n' +
      '🎙️ Управление голосом владельца: в Настройках → «Голосовой помощник» появился пункт «Голос владельца» — можно посмотреть статус, записать образец заново или удалить его (ассистент вернётся к обычному режиму).\n\n' +
      '🎧 Звонки: при переключении в другое приложение (например, WhatsApp) и возврате звук больше не слетает с наушников на громкую связь — приложение теперь уважает фактически подключённое устройство.\n\n' +
      '🌐 Переводчик: если назвать языки («переводи с русского на китайский»), пара языков выставляется сразу и правильно — раньше флаги могли залипнуть на 🇷🇺+🇬🇧.\n\n' +
      '💬 Ваши реплики в чате с ассистентом теперь появляются в правильном порядке — до ответа, а не после. Реплики посторонних (телевизор, чужая речь), отклонённые фильтром голоса владельца, больше не остаются в переписке.',
    notes_en:
      'Release 1.1.9 — voice assistant and call refinements.\n\n' +
      '🎙️ Owner voice management: Settings → Voice Assistant now has an "Owner voice" entry — check status, re-record the sample, or delete it (the assistant returns to normal mode).\n\n' +
      '🎧 Calls: switching to another app (e.g. WhatsApp) and back no longer knocks audio off your headphones onto the loudspeaker — the app now respects the actually connected device.\n\n' +
      '🌐 Translator: naming the languages ("translate between Russian and Chinese") locks the correct pair immediately — flags used to get stuck on 🇷🇺+🇬🇧.\n\n' +
      '💬 Your messages in the assistant chat now appear in the correct order — before the answer, not after. Bystander speech (TV, other people) rejected by the owner-voice filter no longer lingers in the transcript.',
  },
  {
    version: '1.1.8',
    build: 206,
    date: '2026-07-03',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.8 — голос хозяина для AI-ассистента.\n\n' +
      '🎙️ Ассистент теперь может узнавать твой голос. При первом открытии ассистента появится предложение записать короткий образец голоса (~15 секунд). После записи ассистент будет реагировать только на голос владельца аккаунта — и игнорировать телевизор, коллег рядом или чужую речь в комнате.\n\n' +
      '🔒 Образец голоса хранится как математический отпечаток (embedding), само аудио не сохраняется. Запись можно удалить в любой момент — ассистент вернётся к обычному режиму.\n\n' +
      'Функция экспериментальная: если распознавание сработает неверно, ассистент продолжит работать как раньше, без блокировки.',
    notes_en:
      'Release 1.1.8 — owner voice for the AI assistant.\n\n' +
      '🎙️ The assistant can now recognise your voice. On first open you will be offered to record a short voice sample (~15 seconds). Once enrolled, the assistant reacts only to the account owner’s voice — ignoring the TV, nearby colleagues, or other people speaking in the room.\n\n' +
      '🔒 The voice sample is stored as a mathematical fingerprint (embedding); the audio itself is not kept. You can delete the enrollment at any time and the assistant returns to normal mode.\n\n' +
      'This feature is experimental: if recognition misfires, the assistant keeps working as before without locking you out.',
  },
  {
    version: '1.1.7',
    build: 205,
    date: '2026-06-27',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.7 — пакет фиксов для звонков.\n\n' +
      '🔊 Громкая связь больше не сбрасывается при сворачивании окна звонка. Если ты включил динамик и свернул приложение — звук останется на динамике, когда ты вернёшься в звонок (раньше тихо переключался на разговорный).\n\n' +
      '📞 Имя собеседника в истории звонков теперь отображается корректно даже у контактов, у которых заполнен только username (без имени/фамилии). Раньше такие звонки помечались UUID-ом — было непонятно кто звонил.\n\n' +
      '🔀 Если вы и собеседник одновременно набираете друг друга — больше не будет второго звонка поверх первого. Вместо этого появится выбор: «Принять его» (роняет твой исходящий, поднимаешь его звонок) или «Остаться на своём» (отбиваешь его, твой звонок продолжается).\n\n' +
      '🎧 Если у собеседника видно индикатор речи (кружок мигает), но звука не слышно — приложение теперь автоматически восстанавливает аудио-трек (раньше единственный workaround был перезвонить).',
    notes_en:
      'Release 1.1.7 — voice call fix bundle.\n\n' +
      '🔊 Speakerphone no longer reverts to earpiece when minimising the call screen. If you enabled the speaker and backgrounded the app, audio stays on the speaker when you come back (previously it silently switched back to the earpiece).\n\n' +
      '📞 The contact name in call history is now shown correctly even for contacts who only have a username (no first/last name). Previously such calls were tagged with a UUID and you could not tell who called.\n\n' +
      '🔀 When you and your contact dial each other at the same moment — no more second ringing call layered on top of the first. Instead you get a choice: "Pick up theirs" (drops your outgoing, picks up their call) or "Stay on mine" (declines theirs, your call keeps ringing).\n\n' +
      '🎧 If the speaking indicator for the remote peer is ticking but you hear nothing, the app now automatically recovers the audio track (previously the only workaround was to hang up and call again).',
  },
  {
    version: '1.1.6',
    build: 204,
    date: '2026-06-25',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.6\n\n' +
      'Убраны цветные тени вокруг логотипа на заставке и в экране ассистента — хром-иконка теперь выглядит чище.\n' +
      'Улучшена маска иконки для светлой темы: устранён оранжевый ореол на белом фоне.',
    notes_en:
      'Release 1.1.6\n\n' +
      'Removed coloured glow shadows around the logo on the splash screen and in the assistant screen — the chrome icon now looks cleaner.\n' +
      'Tightened the light-theme icon mask to eliminate the orange halo on white backgrounds.',
  },
  {
    version: '1.1.5',
    build: 203,
    date: '2026-06-25',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.5\n\n' +
      'Исправлен экран исходящего звонка.\n' +
      'При нажатии кнопки звонка теперь сразу видно имя и аватар собеседника и слышны гудки — как было до версии 1.1.3.',
    notes_en:
      'Release 1.1.5\n\n' +
      'Fixed outgoing call screen.\n' +
      'Tapping the call button now immediately shows the callee\'s name and avatar with a ringback tone — restoring behaviour from before 1.1.3.',
  },
  {
    version: '1.1.4',
    build: 202,
    date: '2026-06-25',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.4 — Новая хром-иконка + чёткие иконки на маленьких размерах.\n\n' +
      'Обновлён дизайн иконки приложения — теплее свечение по контуру (вместо холодного chrome в 1.1.2/1.1.3). Иконка одна на трёх треках (DEV / TEST / Taler ID), различие — только в названии под иконкой.\n\n' +
      'Чинит замыленные иконки на маленьких размерах (60×60 / 120×120 на home screen, лаунчер, нотификации): теперь все размеры генерятся через ImageMagick с Lanczos + unsharp вместо встроенного билинейного даунсемплинга — детали и тонкие линии (точки контура, светлые блики) видны на любом размере.\n\n' +
      'Без функциональных изменений — продолжение визуального refresh.',
    notes_en:
      'Release 1.1.4 — New chrome icon + crisp small-size rendering.\n\n' +
      'Refreshed app icon design — warmer outline glow (vs the colder chrome in 1.1.2/1.1.3). Same icon across all three tracks (DEV / TEST / Taler ID); only the name under the icon differs.\n\n' +
      'Fixes the blurry small-size icons (60×60 / 120×120 on home screen, launcher, notifications): every size is now generated via ImageMagick Lanczos + unsharp instead of the default bilinear downsample — fine details (contour dots, highlights) stay visible at every size.\n\n' +
      'No functional changes — continuation of the visual refresh.',
  },
  {
    version: '1.1.3',
    build: 201,
    date: '2026-06-25',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.3 — Иконка вместо видео на сплеше и в Ассистенте + новый launch screen.\n\n' +
      'Пульсирующее видео-лого, которое крутилось в центре splash-экрана и в AI-Ассистенте (на idle, в активной сессии и при загрузке), заменено на статическую хром-иконку. На светлой теме — chrome с прозрачным фоном поверх белой подложки; на тёмной — chrome на чёрной подложке.\n\n' +
      'Также обновлены native launch-screens, которые показываются ДО загрузки Flutter:\n' +
      '• Android — хром-иконка из mipmap/ic_launcher поверх чёрного фона.\n' +
      '• iOS — настоящая хром-иконка 200/400/600 px вместо прежней 1×1 заглушки, фон сменился с синего на чёрный.\n\n' +
      'Никаких функциональных изменений — продолжение визуального refresh, начатого в 1.1.2.',
    notes_en:
      'Release 1.1.3 — Static icon instead of looping video on splash and Assistant + new native launch screen.\n\n' +
      'The pulsing video logo that played in the centre of the splash screen and the AI Assistant (idle, active, and loading states) is replaced with the static chrome icon. On light theme — chrome with transparent background over a white pad; on dark theme — chrome over a black pad.\n\n' +
      'Native launch screens (shown BEFORE Flutter loads) are also updated:\n' +
      '• Android — chrome icon from mipmap/ic_launcher over a black background.\n' +
      '• iOS — real chrome icon at 200/400/600 px instead of the previous 1×1 placeholder, background switched from blue to black.\n\n' +
      'No functional changes — continuation of the visual refresh started in 1.1.2.',
  },
  {
    version: '1.1.2',
    build: 200,
    date: '2026-06-24',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.2 — Обновлённая иконка приложения.\n\n' +
      'Новый дизайн иконки — хромированная скульптурная форма на чёрном фоне (взамен прежней «звезды»). Иконка теперь одна и та же на трёх треках (DEV / TEST / Taler ID), различие сохраняется только в названии под иконкой («DEV Taler ID», «TEST Taler ID», «Taler ID»). Внутри приложения логотипы на сплеше, экране входа, AI-ассистенте и в профиле тоже обновлены под новый дизайн.\n\n' +
      'Никаких изменений в функциональности — только обновление визуального бренда.',
    notes_en:
      'Release 1.1.2 — Refreshed app icon.\n\n' +
      'New icon design — chrome sculptural shape on black background (replacing the previous "star"). The icon is now the same across all three tracks (DEV / TEST / Taler ID); they remain distinguishable by the name under the icon ("DEV Taler ID", "TEST Taler ID", "Taler ID"). In-app branding on splash, login, AI assistant, and profile screens has been updated to match.\n\n' +
      'No functional changes — purely a visual brand refresh.',
  },
  {
    version: '1.1.1',
    build: 198,
    date: '2026-06-22',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.1 — Три-трековая схема (DEV / TEST / Taler ID).\n\n' +
      '⚠️ Иконка приложения переименовалась.\n' +
      'Текущий aeza-прод (та сборка, которую ты сейчас обновляешь) теперь называется **«TEST Taler ID»**. Это не баг и не другое приложение — просто переименование, чтобы было видно где какая среда. Никаких миграций / повторного логина не нужно — все твои чаты, контакты, настройки на месте.\n\n' +
      'Зачем: в продукт добавлен **новый «настоящий» прод на DigitalOcean** (Taler ID без префикса, домен api.talerid.io). Параллельно с aeza-сетью, более устойчивый, ближе к Европе. Cutover ещё не сделан — DO-прод пока «тихий», но инфраструктура готова и доступна как отдельное приложение (`io.talerid.app`, для iOS — App Store запись «Taler ID»).\n\n' +
      'Чтобы было понятно где какая версия:\n' +
      '• Иконка «DEV Taler ID» — internal-staging (aeza staging.id.taler.tirol)\n' +
      '• Иконка «TEST Taler ID» — стабильная test-среда (aeza id.taler.tirol). **Это твоя сборка**.\n' +
      '• Иконка «Taler ID» (без префикса) — будущий канонический PROD (DO api.talerid.io). Появится позже отдельным приложением.\n\n' +
      'Внутри приложения, на экране Настройки → раздел с версией, теперь тоже виден префикс окружения (например «TEST 1.1.1+198») — чтобы не было путаницы при отчётах о багах.',
    notes_en:
      'Release 1.1.1 — Three-track naming (DEV / TEST / Taler ID).\n\n' +
      '⚠️ Your app icon has been renamed.\n' +
      'The current aeza prod build (the one you are upgrading now) is now called **"TEST Taler ID"**. This is not a different app — just a rename so each environment is visible at a glance. No migration / re-login needed — all your chats, contacts, settings stay.\n\n' +
      'Why: a **new canonical prod on DigitalOcean** has been added to the product (Taler ID with no prefix, domain api.talerid.io). Parallel to the aeza stack, more resilient, closer to Europe. Cutover is not done yet — DO prod is still quiet, but infrastructure is ready and exposed as a separate app (`io.talerid.app`, iOS App Store entry "Taler ID").\n\n' +
      'So you can tell builds apart:\n' +
      '• "DEV Taler ID" icon — internal staging (aeza staging.id.taler.tirol)\n' +
      '• "TEST Taler ID" icon — stable test track (aeza id.taler.tirol). **This is your build.**\n' +
      '• "Taler ID" icon (no prefix) — future canonical PROD (DO api.talerid.io). Coming later as a separate app.\n\n' +
      'Inside the app, the Settings screen now shows the environment prefix next to the version (e.g. "TEST 1.1.1+198") so bug reports are not ambiguous.',
  },
  {
    version: '1.1.0',
    build: 197,
    date: '2026-06-22',
    flavor: 'both',
    notes_ru:
      'Релиз 1.1.0\n\n' +
      'AI Обзвон — фича полностью удалена из продукта (Фаза 2).\n' +
      'В 1.0.99 убрали тайл и заблокировали создание новых кампаний; теперь удалены и обработчик сообщений в мессенджере, и весь модуль на бэкенде. Любые остатки AI_OUTBOUND-чатов рендерятся как обычные DIRECT-разговоры без бот-функциональности. Никаких пользовательских действий не требуется.\n\n' +
      'Дальше планируется: вывод из эксплуатации связанной инфраструктуры (DigitalOcean dispatcher, Selectel Asterisk, SIPNET trunk, Voximplant) и удаление таблиц истории кампаний из БД — отдельным шагом после подтверждения, что in-flight кампании отстрелялись.',
    notes_en:
      'Release 1.1.0\n\n' +
      'AI Outbound Caller — feature fully removed from the product (Phase 2).\n' +
      '1.0.99 removed the tile and blocked new campaign creation; this release deletes the messenger handler and the entire backend module. Any leftover AI_OUTBOUND chats render as regular DIRECT conversations with no bot functionality. No user action required.\n\n' +
      'Next steps: decommissioning of the supporting infrastructure (DigitalOcean dispatcher, Selectel Asterisk, SIPNET trunk, Voximplant) and dropping the campaign history tables — separate step pending confirmation that in-flight campaigns have finished.',
  },
  {
    version: '1.0.99',
    build: 196,
    date: '2026-06-22',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.99\n\n' +
      'AI Обзвон — фича выпиливается из продукта. Закреплённый тайл «AI Обзвон» больше не появляется в списке чатов, новые кампании создать нельзя (бэкенд отвечает 410 Gone). Уже идущие кампании доиграют до конца. В следующих релизах сервис будет полностью удалён вместе с инфраструктурой (DigitalOcean dispatcher, Selectel Asterisk, Voximplant, SIPNET).',
    notes_en:
      'Release 1.0.99\n\n' +
      'AI Outbound Caller — feature is being sunset. The pinned "AI Caller" tile is gone from the chat list and no new campaigns can be created (backend returns 410 Gone). Any in-flight campaigns will finish on their own. Following releases will remove the service entirely along with its infrastructure (DigitalOcean dispatcher, Selectel Asterisk, Voximplant, SIPNET).',
  },
  {
    version: '1.0.98',
    build: 195,
    date: '2026-06-18',
    flavor: 'both',
    notes_ru:
      'Hotfix 1.0.98\n\n' +
      'Мессенджер — добили фантомные сообщения, которые иногда «выстреливали» из старой очереди черновиков.\n' +
      'Симптом: внезапно из твоего аккаунта в разные чаты улетают сообщения, которые ты набирал когда-то давно и забыл (пример: «Не выдерживает твоего напора» прилетал то одному контакту, то другому через недели после написания).\n\n' +
      'Что было: в 1.0.86 уже починили основной сценарий — очистку очереди при logout + фильтр по автору. Но записи, попавшие в локальный кэш ДО 1.0.86, оставались без полей «автор» и «время отправки». Старый код считал такие записи «непонятными → оставить на потом», и они продолжали ретраиться на каждом реконнекте сокета — месяцами.\n\n' +
      'Что сделали: жёсткая политика — запись отправляется только если в ней одновременно есть твой userId как автор И валидное время отправки в пределах 7 дней. Любая запись без этих полей или с чужим автором или старше 7 дней — выкидывается, не отправляется. Старые легаси-записи дренируются за один проход после установки 1.0.98.',
    notes_en:
      'Hotfix 1.0.98\n\n' +
      'Messenger — finished off the phantom messages that occasionally "fired" out of the stale draft queue.\n' +
      'Symptom: suddenly your account would send into various chats messages you had typed long ago and forgotten (example: "Не выдерживает твоего напора" landing in random contacts\' chats weeks after authoring).\n\n' +
      'Background: 1.0.86 already covered the main case — wipe queue on logout + filter by author. But entries written to the local cache BEFORE 1.0.86 had no "author" or "sentAt" fields. The old guards treated such entries as "unknown → keep for later", so they kept retrying on every socket reconnect — for months.\n\n' +
      'Changes: strict policy — a draft is resent only if it has both your userId as author AND a valid sentAt within 7 days. Any entry missing those fields, or owned by a different account, or older than 7 days is evicted, not sent. All legacy pre-1.0.86 entries are flushed in a single pass after upgrading to 1.0.98.',
  },
  {
    version: '1.0.97',
    build: 194,
    date: '2026-06-21',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.97 — Informer V2.\n\n' +
      'Этот релиз только для 4 операторов GsmSoft с включённым доступом informerAccess. Обычные пользователи никаких отличий не заметят.\n\n' +
      'Цветные бейджи в Informer-чате. ' +
      'Markdown-рендерер теперь понимает цветные теги: hot-кошельки помечаются красным бейджем, cold — синим, low-balance — жёлтым, OK — зелёным. Балансы в hot-роли подкрашены красным, в cold — синим. Раньше всё было чёрно-белым и приходилось вчитываться чтобы найти проблему. Цвета помогают глазом сразу увидеть «где плохо». Поддерживается и в сообщениях существующих ботов AI Аналитик / AI Обзвон — если они когда-то начнут эмитить цветные теги, отрендерится автоматически.\n\n' +
      'Авто-алёрт «Hot нужно пополнить».\n' +
      'Каждые 5 минут бэкенд считает: суммарный pending withdrawal по сети-токену против текущего баланса hot-кошелька. Если pending больше 90% от hot (т.е. не хватит даже с 10% буфером) — каждый из 4 операторов получает в Informer-чате алёрт:\n' +
      '🔴 **Refill needed** [STAGE 1] — список затронутых пар, сколько надо пополнить.\n' +
      'Если через 30 минут дефицит не закрыт — приходит follow-up [STAGE 2 — UNRESOLVED]. Ещё через час — [STAGE 3 — ESCALATED]. Дальше тишина (чтобы не спамить).\n' +
      'Под алёртом четыре кнопки управления:\n' +
      '• ✅ Понял, работаю — алёрты этой цепочки уходят на 30 минут\n' +
      '• 🔕 Заглушить 1 час — на час\n' +
      '• 🔕 До утра 9:00 — до следующего 9:00 по Берлину (DST-aware: зимой UTC+1, летом UTC+2)\n' +
      '• 🔇 Совсем отключить — алёрты больше не приходят пока не нажмёшь Включить обратно\n' +
      'Управление per-user: один оператор нажал «Понял» — у других эскалация продолжается.\n\n' +
      'Кнопка ⚙️ Настройки алёртов в welcome-сообщении показывает текущее состояние (Активно / Заглушено до X / Отключено) и даёт переключатели.\n\n' +
      'Дашборд балансов в евро.\n' +
      'Новая кнопка [💶 Балансы в евро] в Informer-чате выдаёт сводку:\n' +
      '• Mini-acquiring — total в евро + breakdown по сетям, HOT/COLD строки с цветом\n' +
      '• Gateway — total + breakdown\n' +
      '• Total per pool в зелёном бейдже если > €10 000, в жёлтом если меньше\n' +
      'Курсы тянутся из CoinGecko (USDT/USDC/BTC/ETH/BNB/TRX), для TAL зашит фиксированный курс 1 TAL = €10 800. Кэш на 15 минут — повторное нажатие моментальное. Кнопка 🔄 Обновить курсы принудительно сбрасывает кэш.\n' +
      'Если CoinGecko недоступен — показываем последний удачный кэш с пометкой «из старого кэша N минут назад», в худшем случае — только native (BTC, ETH и т.д.) без EUR.\n\n' +
      'Также: накопились непубликованные изменения с 1.0.89 — звонки через TURN для CIS-сегмента (turn.talerid.io), мгновенный экран «Calling…» при тапе на звонок (без dead-tap паузы).',
    notes_en:
      'Release 1.0.97 — Informer V2.\n\n' +
      'This release is only relevant for the 4 GsmSoft operators with the informerAccess flag enabled. Regular users will see no difference.\n\n' +
      'Coloured badges in the Informer chat. ' +
      'The markdown renderer now understands colour tags: hot wallets get a red badge, cold gets blue, low-balance yellow, OK green. Balances inside the hot role are tinted red, cold are blue. Previously the chat was monochrome and you had to read every row to spot a problem. Colours give an at-a-glance signal of where the trouble is. The renderer also activates for AI Analyst / AI Outbound bot messages — if they ever start emitting colour tags, they render automatically.\n\n' +
      'Automatic "Hot needs refill" alerts.\n' +
      'Every 5 minutes the backend computes total pending withdrawals per (network, token) against the current hot-wallet balance. If pending exceeds 90% of hot (i.e. cannot be served even with a 10% buffer), each of the 4 operators receives an Informer-chat alert:\n' +
      '🔴 **Refill needed** [STAGE 1] — list of affected pairs and how much to top up.\n' +
      'If the deficit is still there after 30 minutes, a follow-up [STAGE 2 — UNRESOLVED] follows. Another hour later — [STAGE 3 — ESCALATED]. Then silence (so we never spam).\n' +
      'Each alert ships with four control buttons:\n' +
      '• ✅ Acknowledged — snoozes this chain for 30 minutes\n' +
      '• 🔕 Snooze 1 hour\n' +
      '• 🔕 Until 9 AM — snoozes until the next 09:00 Berlin time (DST-aware: CET in winter, CEST in summer)\n' +
      '• 🔇 Disable completely — no more alerts until you tap Enable again\n' +
      'Per-user state: one operator pressing Acknowledged does not reset the escalation timer for the others.\n\n' +
      'A ⚙️ Alert settings button in the welcome message shows current state (Active / Snoozed until X / Disabled) and toggle controls.\n\n' +
      'EUR balances dashboard.\n' +
      'New [💶 EUR balances] button in the Informer chat returns a digest:\n' +
      '• Mini-acquiring — EUR total + per-chain breakdown, HOT/COLD rows colour-coded\n' +
      '• Gateway — total + breakdown\n' +
      '• Per-pool total in a green badge if above €10 000, yellow otherwise\n' +
      'Rates pulled from CoinGecko (USDT/USDC/BTC/ETH/BNB/TRX); for TAL a hardcoded 1 TAL = €10 800 is used. Cache is 15 minutes — repeat taps are instant. 🔄 Refresh rates button forcibly invalidates the cache.\n' +
      'If CoinGecko is unreachable, the digest shows the last successful cache with a "stale by N minutes" banner; worst case — native only (BTC, ETH, etc.) without EUR.\n\n' +
      'Also: backlog since 1.0.89 — calls via TURN for CIS segments (turn.talerid.io), and an instant "Calling…" screen on tap (no dead-tap pause).',
  },
  {
    version: '1.0.89',
    build: 186,
    date: '2026-06-16',
    flavor: 'both',
    notes_ru:
      'Hotfix 1.0.89\n\n' +
      'Звонки — пропущенный звонок больше не дублируется в чате.\n' +
      'Симптом: один реальный звонок, который никто не взял, оставлял в переписке **два** одинаковых сообщения «📞 Пропущенный звонок» (и заодно «Нет ответа» в шапке вызова показывалось дважды). Причина: при разрыве звонка клиент рассылал событие call_ended по нескольким каналам (socket + HTTP fallback, плюс по триггерам от CallKit/LiveKit/кнопки), а на сервере проверка «уже обработали?» делалась неатомарно — оба обработчика проходили, оба создавали системное сообщение.\n\n' +
      'Что починили:\n' +
      '• Сервер: атомарный SETNX-гейт на roomName — первое событие call_ended делает всё (запись endedAt, missed-call сообщение, FCM-пуш), последующие игнорируются как дубликаты.\n' +
      '• Мобила: добавили per-screen флаг — call_ended уходит на бэкенд ровно один раз за весь жизненный цикл экрана звонка, даже если за время разрыва успели сработать и CallKit-событие, и кнопка «отбой», и room.disconnected от LiveKit.',
    notes_en:
      'Hotfix 1.0.89\n\n' +
      'Calls — missed-call message no longer duplicates in the chat.\n' +
      'Symptom: one missed call left TWO "📞 Missed call" system messages in the conversation, and the call screen showed "No answer" twice. Root cause: client sent call_ended via several paths (socket + HTTP fallback, plus triggers from CallKit / LiveKit / red button), and the server check on "already processed?" was a non-atomic check-then-act — both handlers passed the gate and both ran the side effects.\n\n' +
      'Fixes:\n' +
      '• Server: atomic SETNX gate per roomName — only the first call_ended runs side effects (endedAt update, missed-call message insert, FCM cancel push); subsequent duplicates are ignored.\n' +
      '• Mobile: per-screen flag ensures call_ended is sent to the backend exactly once for the lifetime of the call screen, regardless of how many triggers fire during hangup.',
  },
  {
    version: '1.0.88',
    build: 185,
    date: '2026-06-16',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.88\n\n' +
      'iOS — звонок больше не рвётся после отклонённого WhatsApp.\n' +
      'Сценарий: ты в звонке Taler ID, на iPhone приходит входящий по WhatsApp/Telegram, ты его отклоняешь — раньше после этого аудио в нашем звонке могло пропасть до самого конца, перезайти в звонок не помогало. Причина: при восстановлении аудио-сессии терялся флаг сосуществования с другими VoIP-приложениями, и iOS сразу заново «перетягивал» звук на CallKit того другого приложения. Теперь восстановление повторяет конфигурацию активного звонка один-в-один.\n\n' +
      'Informer Bot — новый бот в мессенджере. Виден только у 4 операторов GsmSoft с включённым доступом (флаг informerAccess на профиле). Показывает: кошельки, требующие действия оператора; балансы mini-acquiring (cold/hot/gas по сетям); системные кошельки crypto-gateway. ' +
      'Кнопки прямо в чате — нажал, через несколько секунд приходит markdown-сводка. ' +
      'Раз в 5 минут бэк сам проверяет API: если появился новый кошелёк, ждущий оператора — сразу алёрт в личный чат каждому из 4-х. Никакого общего канала: каждый видит у себя, читает в своём темпе. ' +
      'Источник данных — Informer API GsmSoft (HMAC-SHA256 подпись, окно ±30с по NTP).',
    notes_en:
      'Release 1.0.88\n\n' +
      'iOS — voice call no longer dies after a declined WhatsApp/Telegram ring.\n' +
      'Scenario: you are in a Taler ID call, a WhatsApp/Telegram VoIP call comes in on iPhone, you decline it — previously the audio of our call could vanish for the rest of the session, even rejoining did not help. Root cause: the AVAudioSession restore path dropped the .mixWithOthers flag, so iOS treated our session as exclusive and immediately reassigned audio to the other app\'s CallKit. Restore path now mirrors the active-call configuration exactly.\n\n' +
      'Informer bot — new messenger bot, visible only to 4 GsmSoft operators with the informerAccess flag on their profile. ' +
      'Shows: operator-required wallets, mini-acquiring balances (cold/hot/gas per chain), gateway system wallets. ' +
      'Buttons in chat — tap and get a markdown snapshot in seconds. ' +
      'Backend polls the API every 5 minutes and pushes a new-wallet alert into each operator\'s personal chat. ' +
      'Data source — GsmSoft Informer API (HMAC-SHA256 signed, ±30s NTP window).',
  },
  {
    version: '1.0.87',
    build: 180,
    date: '2026-06-16',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.87\n\n' +
      'Заметки — починили «зомби-заметки», которые возвращались после удаления.\n' +
      'Симптом: удаляешь заметку из списка, делаешь pull-to-refresh — заметка снова в списке. Со второй попытки удаляется как надо. Причина: pull-to-refresh успевал притянуть актуальный список с сервера ДО того как DELETE-запрос на удаление туда долетал, и локально заметка восстанавливалась обратно. Теперь refresh пропускает сущности с неотправленными outbox-операциями.\n\n' +
      'Синхронный перевод в звонке:\n' +
      '• Появилась явная кнопка «Выключить переводчик» в выпадашке выбора языка (раньше для отключения нужно было тапнуть текущий язык второй раз — не очевидно).\n' +
      '• Громкость голоса собеседника автоматически приглушается до 25% пока работает переводчик, а голос переводчика поднимается до 100%. Когда переводчик выключаешь — громкость собеседника возвращается в норму.',
    notes_en:
      'Release 1.0.87\n\n' +
      'Notes — fixed "zombie notes" that reappeared after deletion.\n' +
      'Symptom: you delete a note from the list, pull-to-refresh — and the note is back. Deleting it a second time works. Root cause: pull-to-refresh fetched the up-to-date server list BEFORE the queued DELETE request reached the server, so the still-present server copy was upserted back locally. refresh() now skips entities with pending/inflight outbox ops.\n\n' +
      'Synchronous call translation:\n' +
      '• New explicit "Turn off translator" entry in the language picker bottom sheet (previously the only way to disable was to tap the already-selected language a second time — undiscoverable).\n' +
      '• While the translator is active, peer voices are auto-ducked to 25% volume and the translator track is boosted to 100% so the translation is intelligible. Turning the translator off restores peer volume to 100%.',
  },
  {
    version: '1.0.86',
    build: 179,
    date: '2026-06-15',
    flavor: 'both',
    notes_ru:
      'Hotfix 1.0.86\n\n' +
      'Мессенджер — починили «фантомные» сообщения, которые отправлялись от твоего имени после смены аккаунта или повторного логина.\n' +
      'Симптом: открываешь приложение, а в чатах с твоего телефона уходят какие-то старые черновики, которых ты сейчас не писал. На Android было заметно особенно — телефон выступал инициатором.\n\n' +
      'Что было: локальная очередь неотправленных сообщений (черновики, которые ставились в очередь при потере сети) переживала logout. На следующем логине очередь сливалась под токеном нового аккаунта.\n\n' +
      'Что сделали:\n' +
      '• При logout очередь черновиков теперь полностью очищается\n' +
      '• На реконнекте сокета учитываем кому реально принадлежит черновик — чужие выкидываются, не отправляются\n' +
      '• Черновики старше 7 дней автоматически удаляются\n' +
      '• Подтверждение от сервера теперь надёжно снимает запись из очереди даже для файловых сообщений и отредактированного текста (раньше там была хрупкая дедупликация по содержимому)',
    notes_en:
      'Hotfix 1.0.86\n\n' +
      'Messenger — fixed "phantom" messages that were being sent under your account after a logout or re-login.\n' +
      'Symptom: you open the app and see your device sending old drafts you didn\'t write right now. Especially visible on Android — the phone showed up as initiator.\n\n' +
      'Root cause: the local outgoing-message queue (drafts saved while offline) survived logout. On the next sign-in it was flushed under the new account\'s JWT.\n\n' +
      'Changes:\n' +
      '• On logout the draft queue is fully wiped\n' +
      '• Socket reconnect now checks draft ownership — drafts from a previous account are evicted, never transmitted\n' +
      '• Drafts older than 7 days are removed automatically\n' +
      '• Server-side acknowledgement now reliably drains the queue even for file messages and edited bodies (previously dedup relied on a fragile content match)',
  },
  {
    version: '1.0.85',
    build: 178,
    date: '2026-06-10',
    flavor: 'both',
    notes_ru:
      'Hotfix 1.0.85\n\n' +
      'Контакты — починили подтверждение запроса в дружбу из вкладки «Контакты».\n' +
      'Раньше: если ты нажимал «Принять» во вкладке Контакты, локально запрос отмечался принятым, но фактически на сервер не уходил — отправитель не видел, что его приняли. Обходной путь был один: открыть профиль через чат и принять оттуда.\n\n' +
      'Теперь:\n' +
      '• Подтверждение/отклонение из вкладки Контакты сразу долетает до бэка\n' +
      '• Любые операции, которые попали в локальную очередь синхронизации, дополнительно дренируются при возвращении из фона — на случай, если ты успел свернуть приложение до того, как они ушли\n\n' +
      'Авторизация — для пользователей с заглавными буквами в email (например, Name@mail.com) восстановление пароля и вход теперь работают в любом регистре. Раньше можно было войти только если ты вводил email точно как при регистрации.',
    notes_en:
      'Hotfix 1.0.85\n\n' +
      'Contacts — fixed accepting a friend request from the Contacts tab.\n' +
      'Previously: tapping "Accept" inside the Contacts tab marked the request accepted locally but never reached the server — the sender did not see the acceptance. The only workaround was to open the profile via Chat and accept from there.\n\n' +
      'Now:\n' +
      '• Accepting/rejecting from the Contacts tab reaches the backend immediately\n' +
      '• Any operations queued in the local sync outbox are additionally drained when the app comes back from the background — in case you backgrounded before they had a chance to flush\n\n' +
      'Authentication — for accounts whose email contains capital letters (e.g. Name@mail.com), password recovery and login now accept any letter case. Previously you could only log in with the exact casing you used at sign-up.',
  },
  {
    version: '1.0.84',
    build: 177,
    date: '2026-06-10',
    flavor: 'both',
    notes_ru:
      'Hotfix 1.0.84\n\n' +
      'Android — починили белый экран при первом запуске после обновления.\n' +
      'У части пользователей после установки 1.0.83 приложение открывалось пустым белым экраном и не реагировало. Причина: системный ключ шифрования (AndroidKeyStore) на устройстве становился невалидным после некоторых системных событий (биометрия, смена пароля, бэкап/рестор), и приложение не могло прочитать сохранённые данные → падало до отрисовки UI.\n\n' +
      'Теперь:\n' +
      '• При обнаружении испорченных данных secure storage автоматически очищается и приложение продолжает запуск\n' +
      '• Пользователю может потребоваться повторный вход (логин + пароль) — это часть фикса\n' +
      '• Цена компромисса: один раз залогиниться заново; альтернатива — белый экран до переустановки',
    notes_en:
      'Hotfix 1.0.84\n\n' +
      'Android — fixed white screen on first launch after update.\n' +
      'Some users saw a blank white screen after updating to 1.0.83. Cause: the system encryption key (AndroidKeyStore) was invalidated by certain system events (biometric re-enroll, lock-screen change, backup/restore), so the app couldn\'t read its saved data → crashed before rendering UI.\n\n' +
      'Now:\n' +
      '• When corrupted secure-storage data is detected, it is wiped automatically and the app continues launching\n' +
      '• You may need to log in again (email + password) — that is part of the fix\n' +
      '• Trade-off: one extra login; alternative was a white screen requiring reinstall',
  },
  {
    version: '1.0.83',
    build: 175,
    date: '2026-06-09',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.83\n\n' +
      'Android — починили обновление приложения.\n' +
      'Раньше при апдейте бывала мутная ошибка «Приложение не установлено, так как оно конфликтует с другим пакетом» — без подсказки что делать. Теперь:\n' +
      '• Когда такая проблема возникает, приложение показывает понятную инструкцию: «Удали старую версию через Настройки → Приложения → Taler ID, открой папку Загрузки в файловом менеджере и тапни talerid-X.Y.Z.apk». Этот шаг нужен один раз.\n' +
      '• Сам APK обновления автоматически кладётся в публичную папку «Загрузки» — можно установить вручную из любого файлового менеджера, если автоматическая установка не пошла.\n' +
      '• Установка идёт через системный установщик Android с понятными сообщениями об ошибках, а не через сторонний просмотрщик файлов.\n\n' +
      'Проверка личности (KYC) — теперь открывается во встроенном WebView, а не через отдельную нативную библиотеку. Пользовательский опыт тот же: документы, селфи, анкета.',
    notes_en:
      'Release 1.0.83\n\n' +
      'Android — fixed app update flow.\n' +
      'Previously app updates could fail with an opaque "App not installed because it conflicts with another package" error — no hint how to recover. Now:\n' +
      '• When this happens, the app shows clear instructions: "Uninstall via Settings → Apps → Taler ID, open the Downloads folder in your file manager, and tap talerid-X.Y.Z.apk." This step is only needed once.\n' +
      '• The update APK is now automatically saved to your public Downloads folder — you can install it manually from any file manager if the in-app install doesn\'t work.\n' +
      '• Installation now goes through Android\'s system installer with clear error messages, instead of a third-party file opener.\n\n' +
      'Identity verification (KYC) — now opens in an embedded WebView instead of a separate native library. Same user experience: documents, selfie, questionnaire.',
  },
  {
    version: '1.0.82',
    build: 174,
    date: '2026-06-08',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.82\n\n' +
      'Новое:\n' +
      '• Подтверждение email — на экране Профиля появилась плашка для тех, у кого email ещё не подтверждён. ' +
      'Нажми «Подтвердить» — придёт 6-значный код на твою почту, введи его, и плашка исчезнет. ' +
      'Подтверждение нужно, чтобы можно было восстановить пароль и получать сервисные уведомления.',
    notes_en:
      'Release 1.0.82\n\n' +
      'New:\n' +
      '• Email verification — Profile now shows a banner if your email is not yet verified. ' +
      'Tap "Verify", a 6-digit code arrives in your inbox; enter it and the banner clears. ' +
      'Verification is required for password recovery and service notifications.',
  },
  {
    version: '1.0.81',
    build: 173,
    date: '2026-05-25',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.81\n\n' +
      'Исправления:\n' +
      '• iOS: восстановление пароля теперь работает на iPhone с iOS 26 — ' +
      'устранили зависание при вводе email (мешала автозаполнение iOS 26, блокировавшая запрос).',
    notes_en:
      'Release 1.0.81\n\n' +
      'Bug fixes:\n' +
      '• iOS: password recovery now works on iPhone with iOS 26 — ' +
      'fixed a freeze when entering email (iOS 26 AutoFill discovery was blocking the request).',
  },
  {
    version: '1.0.80',
    build: 172,
    date: '2026-05-26',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.80\n\n' +
      'Биллинг — закрыли утечку с «висящими» сессиями ассистента:\n' +
      '• Если приложение упало или потерялась сеть прямо во время разговора с AI-ассистентом, ' +
      'на сервере оставалась «активная» сессия — сервер продолжал каждые 10 секунд списывать с баланса, ' +
      'хотя пользователя уже не было. У отдельных аккаунтов накопилось до 10 параллельных таких сессий ' +
      'возрастом до месяца. На проде в момент выкатки разово закрыто ~190 таких зомби-сессий.\n' +
      'Что починили:\n' +
      '  (1) когда WebSocket рвётся, сервер сразу закрывает биллинг-сессию;\n' +
      '  (2) если по какой-то причине не закрылась — серверный «жнец» добивает её принудительно по таймауту ' +
      '(2 часа для голосового ассистента, 1 час для AI-двойника и outbound-звонков).',
    notes_en:
      'Release 1.0.80\n\n' +
      'Billing — closed a leak with "stuck" assistant sessions:\n' +
      '• If the app crashed or the network dropped mid-conversation with the AI assistant, ' +
      'the server kept the session marked active and the cron kept debiting the wallet every 10 s ' +
      'long after the user was gone. Some accounts accumulated up to 10 parallel stuck sessions ' +
      'as old as a month. ~190 such zombies were swept at rollout on PROD.\n' +
      'What we fixed:\n' +
      '  (1) WebSocket drop now ends the billing session immediately on the server;\n' +
      '  (2) hard server-side cap as a safety net — 2 h for voice assistant, 1 h for AI twin ' +
      'and outbound calls.',
  },
  {
    version: '1.0.79',
    build: 171,
    date: '2026-05-25',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.79\n\n' +
      'Десктоп-фиксы:\n' +
      '• Входящие звонки на macOS/Linux/Windows теперь показывают диалог с кнопками «Ответить» / «Отклонить». ' +
      'Раньше сокет получал call_invite, но UI был только в мобильном dashboard — на десктопе пропускали звонок молча.\n' +
      '• Правый клик по сообщению в чате открывает меню действий (ответить, скопировать, переслать, удалить и т.д.). ' +
      'Раньше работал только long-press, которого на десктопе с мышкой нет.\n\n' +
      'Исправления:\n' +
      '• На экране сброса и смены пароля показывалась ошибка «PIN-коды не совпадают» вместо «Пароли не совпадают». Поправили.\n' +
      '• Гостевая ссылка на комнату звонка вида /room/<код> снова открывается в браузере — раньше из браузера выдавалось «Комната не найдена».\n' +
      '• В окне звонка имя собеседника берётся из username, если в профиле не заполнены имя и фамилия. Раньше показывался UUID.',
    notes_en:
      'Release 1.0.79\n\n' +
      'Desktop fixes:\n' +
      '• Incoming calls on macOS/Linux/Windows now show an in-app dialog with Accept / Decline. ' +
      'Previously the socket received call_invite but the UI was only wired in the mobile dashboard — ' +
      'desktop missed calls silently.\n' +
      '• Right-click on a chat message now opens the actions sheet (reply, copy, forward, delete, etc.). ' +
      'Previously only long-press worked, which mice cannot trigger on desktop.\n\n' +
      'Fixes:\n' +
      '• Reset-password and change-password screens showed "PINs don\'t match" instead of "Passwords don\'t match". Fixed.\n' +
      '• Guest link to a call room /room/<code> opens in the browser again — previously the web client showed "Room not found".\n' +
      '• In-call participant name now falls back to username when first/last name are empty, instead of showing the UUID.',
  },
  {
    version: '1.0.78',
    build: 170,
    date: '2026-05-20',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.78\n\n' +
      '🌍 22 новых языка интерфейса:\n' +
      '中文 (китайский), हिन्दी (хинди), Español, العربية (арабский), বাংলা (бенгали), ' +
      'Português, اردو (урду), Bahasa Indonesia, Deutsch, 日本語, Français, मराठी (маратхи), ' +
      'తెలుగు (телугу), Türkçe, தமிழ் (тамильский), Tiếng Việt, 한국어, Italiano, ' +
      'فارسی (фарси), ਪੰਜਾਬੀ (панджаби), Hausa (хауса, Нигерия), Slovenčina.\n' +
      'Всего 24 языка интерфейса (было 2). Меняется в Настройки → Язык.\n\n' +
      '🎙️ AI-ассистент следует языку приложения:\n' +
      'Раньше ассистент всегда говорил по-русски (если ru) или по-английски (для всех остальных). ' +
      'Теперь промпт динамический — выбираешь Español в настройках, ассистент отвечает на испанском. ' +
      'Whisper-транскрипция и до этого корректно подхватывала локаль — теперь обратная сторона тоже выровнена.\n\n' +
      'Качество переводов:\n' +
      'Переводы машинные (GPT-4o) — для первого шипа OK, перед следующим релизом будут полированы носителями. ' +
      'Названия брендов (Taler ID, KYC, Gmail, WhatsApp и т.д.) и плейсхолдеры в строках сохранены как есть.',
    notes_en:
      'Release 1.0.78\n\n' +
      '🌍 22 new UI languages:\n' +
      '中文 (Mandarin), हिन्दी (Hindi), Español, العربية (Arabic), বাংলা (Bengali), ' +
      'Português, اردو (Urdu), Bahasa Indonesia, Deutsch, 日本語, Français, मराठी (Marathi), ' +
      'తెలుగు (Telugu), Türkçe, தமிழ் (Tamil), Tiếng Việt, 한국어, Italiano, ' +
      'فارسی (Persian), ਪੰਜਾਬੀ (Punjabi), Hausa (Nigeria), Slovenčina.\n' +
      '24 UI languages total (was 2). Settings → Language.\n\n' +
      '🎙️ AI assistant follows the app language:\n' +
      'Previously the assistant always responded in Russian (locale ru) or English (everything else). ' +
      'Now the system prompt is locale-aware — pick Español in settings and the assistant replies in Spanish. ' +
      'Whisper input was already pinned to the app locale — this completes the round-trip.\n\n' +
      'Translation quality:\n' +
      'Translations are machine-generated (GPT-4o) — good enough to ship, will be reviewed by native ' +
      'speakers before the next release. Brand names (Taler ID, KYC, Gmail, WhatsApp etc.) and string ' +
      'placeholders preserved verbatim.',
  },
  {
    version: '1.0.77',
    build: 169,
    date: '2026-05-20',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.77\n\n' +
      'AI-ассистент дотягивается до соседних мессенджеров и почты:\n' +
      '• Android: ассистент видит уведомления WhatsApp и Telegram и может ' +
      'на них отвечать за тебя (только после ручного включения доступа к уведомлениям в системе).\n' +
      '• Gmail: ассистент подключается через OAuth и работает со всеми твоими почтами — ' +
      'может читать письма, искать по теме/отправителю/телу, отвечать и отправлять новые.\n' +
      '• Бот «Ассистент» в чатах получил кнопку микрофона в шапке — мгновенный переход в голосовой режим.\n\n' +
      'Десктоп:\n' +
      '• Тап по «Ассистент» в левой панели сразу запускает голосовую сессию (без промежуточного «колеса»).\n' +
      '• В левую панель добавлены Notes, Contacts, Profile — теперь вся навигация в одном месте.\n' +
      '• В чате Enter отправляет сообщение, Cmd/Ctrl+Enter переносит строку.\n' +
      '• Сообщения в мессенджере подгружаются сразу при открытии экрана (без переключения вкладок).\n' +
      '• Новый онбординг под десктоп с кликабельными подсказками для системных настроек.\n\n' +
      'AI-аналитик:\n' +
      '• Сгенерированные PDF/отчёты теперь правильно прикладываются к сообщению ' +
      '(раньше ассистент говорил «приложил», а файла не было).',
    notes_en:
      'Release 1.0.77\n\n' +
      'AI assistant reaches into neighbouring messengers and email:\n' +
      '• Android: the assistant sees WhatsApp and Telegram notifications and can reply on your behalf ' +
      '(after you grant notification access in system settings).\n' +
      '• Gmail: the assistant connects via OAuth and works across all your inboxes — ' +
      'read messages, search by subject/sender/body, reply and compose new mail.\n' +
      '• The Assistant bot in chats got a microphone button in the title bar — one-tap into voice mode.\n\n' +
      'Desktop:\n' +
      '• Clicking "Assistant" in the left rail starts a voice session immediately (no more orbital wheel).\n' +
      '• Notes, Contacts and Profile are now in the left rail — all navigation in one place.\n' +
      '• In chat, Enter sends, Cmd/Ctrl+Enter inserts a newline.\n' +
      '• Messages now load instantly when you open the messenger tab.\n' +
      '• New desktop onboarding with clickable links to system settings.\n\n' +
      'AI analyst:\n' +
      '• Generated PDFs and reports are now correctly attached to the message ' +
      '(previously the assistant claimed to attach a file but nothing came through).',
  },
  {
    version: '1.0.76',
    build: 168,
    date: '2026-05-18',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.76\n\n' +
      'Выход из аккаунта:\n' +
      '• На logout стираются все следы прошлого пользователя — отзывается FCM-токен, ' +
      'снимаются зависшие CallKit оверлеи, очищаются маппинги контактов в mesh и ' +
      'локальная история сообщений. Перелогин под другой аккаунт больше не показывает ' +
      'имена предыдущего юзера в списке контактов и групповых звонках.\n\n' +
      'AI-ассистент:\n' +
      '• Бэкенд /voice/session переехал на GA Realtime API.\n' +
      '• Модель ассистента обновлена до gpt-realtime-mini-2025-12-15.',
    notes_en:
      'Release 1.0.76\n\n' +
      'Sign-out cleanup:\n' +
      '• Logout now wipes every trace of the previous user — FCM token is revoked, ' +
      'stuck CallKit overlays are dismissed, mesh contact mappings are cleared, ' +
      "and local message history is purged. Re-login under a different account no longer " +
      "shows the prior user's names in contacts or group calls.\n\n" +
      'AI assistant:\n' +
      '• Backend /voice/session migrated to the GA Realtime API.\n' +
      '• Assistant model upgraded to gpt-realtime-mini-2025-12-15.',
  },
  {
    version: '1.0.74',
    build: 167,
    date: '2026-05-15',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.74\n\n' +
      'Десктоп:\n' +
      '• Первый официальный релиз приложений для macOS, Windows и Linux. ' +
      'Скачать на https://id.taler.tirol\n\n' +
      'Обновления внутри приложения:\n' +
      '• Когда выходит новая версия, баннер показывает changelog ' +
      '(а не просто "доступно обновление").\n' +
      '• На Android APK теперь скачивается прямо из приложения без перехода в браузер.\n' +
      '• Эндпоинт /app/version отдаёт релизы с раздельным таргетом для dev/prod флейворов.\n\n' +
      'AI-ассистент:\n' +
      '• Знает о текущей версии и changelog — можно спросить "что нового в этой версии?".',
    notes_en:
      'Release 1.0.74\n\n' +
      'Desktop:\n' +
      '• First official release of macOS, Windows and Linux desktop apps. ' +
      'Download from https://id.taler.tirol\n\n' +
      'In-app updates:\n' +
      '• Update banner now shows the changelog when a new version is available, ' +
      'instead of a generic "update available" prompt.\n' +
      '• Android APK now downloads in-app without bouncing through the browser.\n' +
      '• /app/version endpoint returns releases with per-flavor (dev/prod) update target.\n\n' +
      'AI assistant:\n' +
      '• Knows the current version and changelog — ask "what is new in this release?".',
  },
  {
    version: '1.0.73',
    build: 178,
    date: '2026-05-15',
    flavor: 'dev',
    notes_ru:
      'Релиз 1.0.73 (тестовая сборка)\n\n' +
      'Групповые звонки по локальной сети (mesh):\n' +
      '• Стабилизация аудио в групповых звонках iOS↔Android\n' +
      '• Дозапись микрофона в фиксированные 20-мс блоки против щелчков\n' +
      '• Авто-восстановление аудиосессии после CallKit\n\n' +
      'Сообщения:\n' +
      '• Размер шрифта плитки «Избранное» выровнен с остальными чатами',
    notes_en:
      'Release 1.0.73 (beta)\n\n' +
      'Mesh group calls:\n' +
      '• Audio stability across iOS↔Android peers\n' +
      '• Mic capture rebuffered into fixed 20 ms chunks to remove clicks\n' +
      '• Audio session auto-recovery after CallKit cycles\n\n' +
      'Messenger:\n' +
      '• Saved chat tile typography aligned with the rest of the chat list',
  },
  {
    version: '1.0.72',
    build: 165,
    date: '2026-05-14',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.72\n\n' +
      'Чат:\n' +
      '• Новое: время в сети\n' +
      '  — В шапке чата и в профиле собеседника: «в сети» или «был(а) в сети 15 мин назад»\n' +
      '  — Обновляется автоматически каждые 30 секунд\n' +
      '  — Настройка приватности в «Изменить профиль → Конфиденциальность»: Все / Только контакты / Никто',
    notes_en:
      'Release 1.0.72\n\n' +
      'Chat:\n' +
      '• New: last-seen indicator\n' +
      '  — Chat header and user profile show "online" or "last seen 15 min ago"\n' +
      '  — Auto-refresh every 30 seconds\n' +
      '  — Privacy controls in "Edit profile → Privacy": Everyone / Contacts / Nobody',
  },
  {
    version: '1.0.71',
    build: 164,
    date: '2026-05-14',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.71\n\n' +
      'Офлайн-режим:\n' +
      '• Заметки — создание, редактирование, удаление работают без интернета\n' +
      '• Календарь — события создаются/редактируются офлайн, конфликты решаются через диалог\n' +
      '• Контакты — приём и отклонение заявок работают офлайн\n' +
      '• Избранное — мгновенный вход в Сохранённые после первого онлайн-открытия\n\n' +
      'Мессенджер:\n' +
      '• AI-ассистент: ответы фоновых задач доставляются через delta-sync, нет потерь при кратком офлайне\n' +
      '• Чат: переподключение сокета при перелогине в другой аккаунт\n\n' +
      'Звонки (групповые mesh):\n' +
      '• Mesh group voice room v1 — групповой звонок 2–5 участников по локальной сети\n' +
      '• Late-joiner audio isolation, per-peer Noise сессии\n' +
      '• Стабильность: CallKit роутинг, lobby flow, GMCEnded маршруты',
    notes_en:
      'Release 1.0.71\n\n' +
      'Offline mode:\n' +
      '• Notes — create, edit, delete work offline\n' +
      '• Calendar — events create/edit offline, conflicts resolved via dialog\n' +
      '• Contacts — accept and reject requests work offline\n' +
      '• Favorites — instant entry into Saved Messages after first online open\n\n' +
      'Messenger:\n' +
      '• AI assistant: background-task replies delivered via delta-sync, no loss after brief offline\n' +
      '• Chat: socket reconnect on relogin into a different account\n\n' +
      'Mesh group calls:\n' +
      '• Mesh group voice room v1 — 2-5 peers over LAN\n' +
      '• Late-joiner audio isolation, per-peer Noise sessions\n' +
      '• Stability: CallKit routing, lobby flow, GMCEnded routes',
  },
];
