"""
Taler ID — Outbound Call Agent.

A livekit-agents worker that joins a LiveKit room and conducts an outbound
phone call to a business on behalf of the user. Asks specific questions
(from campaign metadata), records the conversation, and posts results
back to the backend.

Dispatched by the Taler ID backend via LiveKit AgentDispatchService
(agent_name="outbound-call-agent"). Per-call settings are passed via
job metadata as JSON.
"""

import json
import logging
import os

import aiohttp
from dotenv import load_dotenv
from livekit.agents import (
    Agent,
    AgentSession,
    JobContext,
    RoomInputOptions,
    WorkerOptions,
    cli,
)
from livekit.plugins import deepgram, elevenlabs, openai, silero
from openai import AsyncOpenAI

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:3000")
CALLBACK_SECRET = os.getenv("OUTBOUND_CALLBACK_SECRET", "outbound-secret-2026")

logger = logging.getLogger("outbound-call-agent")
logging.basicConfig(level=logging.INFO)

# Use ElevenLabs for natural Russian speech (same as ai-twin-agent)
USE_ELEVENLABS = True
ELEVENLABS_VOICE_ID = "13JzN9jg1ViUP8Pf3uet"
OPENAI_VOICE = "shimmer"  # fallback if ElevenLabs not available


def _build_instructions(metadata: dict) -> str:
    business_name = metadata.get("businessName", "компания")
    questions = metadata.get("questionsToAsk", [])
    task_context = metadata.get("taskContext", "")
    custom_prompt = metadata.get("agentPrompt", "")

    questions_text = "\n".join(f"  {i+1}. {q}" for i, q in enumerate(questions))

    owner_name = metadata.get("ownerName", "клиент")

    # If user provided a custom prompt, use it as the base
    if custom_prompt:
        return f"""{custom_prompt}

Сейчас звоню в "{business_name}".
Задача: {task_context}

Вопросы:
{questions_text}

Правила: будь кратким, вежливым, по-деловому. Не более 3 минут.
ВСЕ числа произноси СЛОВАМИ ("один миллион", "пятьсот тысяч"). НЕ используй цифры.
Телефонные номера диктуй по две-три цифры с паузами."""

    # Determine task type: booking vs info gathering
    task_lower = task_context.lower()
    is_booking = any(w in task_lower for w in [
        'записать', 'запись', 'забронировать', 'бронь', 'заказать',
        'назначить', 'записаться', 'забукать', 'book', 'reserve',
    ])

    if is_booking:
        action_rules = """- Твоя цель — ЗАПИСАТЬСЯ / ЗАБРОНИРОВАТЬ. Это главная задача.
- Если предлагают записать — СОГЛАШАЙСЯ. Называй нужные данные (имя, время, дату).
- Если записали успешно — подтверди запись, уточни адрес и попрощайся.
- Если нет свободных мест — спроси когда есть и попрощайся.
- НЕ заказывай то, что не относится к задаче."""
    else:
        action_rules = """- Ты ТОЛЬКО узнаёшь информацию. Ничего не заказывай, не записывайся.
- Если предлагают записать — скажи "Я подумаю" или "Мне нужно уточнить".
- Если не знаешь какие-то данные — скажи "Я уточню".\""""

    return f"""Ты обычный человек, который звонит в "{business_name}".
Тебя зовут Алексей. Ты звонишь по просьбе друга.

Задача: {task_context}

Тебе нужно узнать:
{questions_text}

## СТИЛЬ — это ТЕЛЕФОННЫЙ ЗВОНОК, не чат:
- Говори как обычный человек по телефону. Коротко, просто, без лишних формальностей.
- ПЕРВАЯ реплика — ТОЛЬКО приветствие: "Здравствуйте!" — и ВСЁ. Жди ответ собеседника.
- Когда собеседник ответит на приветствие — коротко скажи зачем звонишь (1 предложение) и задай ПЕРВЫЙ вопрос.
- Задавай СТРОГО по ОДНОМУ вопросу за раз. Дождись ответа. Потом следующий.
- НЕ вываливай всю информацию монологом. Собеседник на телефоне не может перечитать.
- НЕ говори "спасибо", "благодарю", "большое спасибо за информацию" после каждой реплики — это звучит неестественно. Одного "спасибо" при прощании достаточно.
- Реагируй на ответы естественно: "Ага", "Понял", "Ясно" — как в обычном разговоре.

## КОНТАКТНЫЕ ДАННЫЕ:
- НЕ оставляй свой номер телефона, если не просят.
- НЕ диктуй номер — в телефонном разговоре это неудобно, человек может не записать.
- Если сделка или запись не состоялась — просто попрощайся. Не надо оставлять контакты.
- Если ПРОСЯТ номер или контакт — скажи "Я перезвоню" или "Мне нужно уточнить, я свяжусь".

## ДЕЙСТВИЯ:
{action_rules}

## ВАЖНО:
- НИКОГДА не придумывай информацию. Не знаешь — скажи "Не знаю" или "Нужно уточнить".
- НЕ используй слова в звёздочках или скобках.
- ВСЕ числа произноси СЛОВАМИ ("пятьсот тысяч", не "500 000").
- Прощание: коротко "До свидания" — и молчи."""


async def _summarize_call(conversation_text: str, metadata: dict, transcript_turns: list) -> str:
    if not conversation_text.strip():
        return ""

    # Не выдумывать, если собеседник реально ничего не сказал.
    user_turns = [t for t in transcript_turns if t.get("role") == "user"]
    user_words = sum(len(str(t.get("text", "")).split()) for t in user_turns)
    meaningful_user = sum(
        1 for t in user_turns
        if len(str(t.get("text", "")).split()) >= 3
    )
    if not user_turns or user_words < 5 or meaningful_user == 0:
        logger.info(
            "[summary] skip: user_turns=%d user_words=%d meaningful=%d",
            len(user_turns), user_words, meaningful_user,
        )
        return "Разговор не состоялся: собеседник не ответил по существу.\nGOAL_ACHIEVED: нет"

    client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    business_name = metadata.get("businessName", "компания")
    task_context = metadata.get("taskContext", "")
    try:
        resp = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": (
                    "Ты суммаризуешь телефонный разговор с компанией. "
                    "КРИТИЧЕСКИ ВАЖНО: опирайся ТОЛЬКО на фактические реплики "
                    "собеседника (Business:) в транскрипте. НЕ выдумывай "
                    "цены, сроки, наличие или контакты, если они не были "
                    "явно названы собеседником. Если данных нет — пиши 'не указано'. "
                    "Если собеседник не ответил по существу (только 'алло' / "
                    "молчание / положил трубку) — верни ровно: "
                    "'Разговор не состоялся.\\nGOAL_ACHIEVED: нет'. "
                    "Иначе формат: "
                    "Компания: X\nЦена: Y\nСроки: Z\nКонтакт: ...\nИтог: ...\n"
                    "GOAL_ACHIEVED: да/нет (была ли выполнена основная задача — "
                    "запись подтверждена, бронь сделана, заказ оформлен и т.д.)"
                )},
                {"role": "user", "content": (
                    f"Компания: {business_name}\n"
                    f"Задача: {task_context}\n\n"
                    f"Транскрипт:\n{conversation_text}"
                )},
            ],
            temperature=0.1,
            max_tokens=400,
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception as e:
        logger.warning("summarize failed: %s", e)
        return ""


async def _post_callback(metadata: dict, transcript: list, summary: str, duration_sec: int) -> None:
    call_id = metadata.get("callId", "")
    campaign_id = metadata.get("campaignId", "")
    callback_url = metadata.get("callbackUrl", f"{BACKEND_URL}/outbound-bot/call-callback")
    callback_secret = metadata.get("callbackSecret") or CALLBACK_SECRET

    payload = {
        "callId": call_id,
        "campaignId": campaign_id,
        "transcript": transcript,
        "summary": summary,
        "durationSec": duration_sec,
        "status": "completed",
    }
    headers = {
        "Content-Type": "application/json",
        "X-Outbound-Secret": callback_secret,
        "x-outbound-secret": callback_secret,
    }
    try:
        async with aiohttp.ClientSession() as http:
            async with http.post(callback_url, json=payload, headers=headers,
                                 timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    logger.warning("[callback] backend returned %s: %s", resp.status, body)
                else:
                    logger.info("[callback] saved call=%s", call_id)
    except Exception as e:
        logger.warning("[callback] POST failed: %s", e)


async def entrypoint(ctx: JobContext):
    await ctx.connect()

    metadata: dict = {}
    raw_metadata = ctx.job.metadata if ctx.job else None
    if raw_metadata:
        try:
            metadata = json.loads(raw_metadata)
        except json.JSONDecodeError:
            logger.warning("Failed to parse job metadata: %r", raw_metadata)

    business_name = metadata.get("businessName", "компания")
    instructions = _build_instructions(metadata)

    # Set display name
    try:
        await ctx.room.local_participant.set_name(f"AI Caller ({business_name})")
    except Exception as e:
        logger.warning("Failed to set name: %s", e)

    logger.info("Outbound call: room=%s business=%s", ctx.room.name, business_name)

    import time
    start_time = time.time()

    vad = silero.VAD.load()
    stt = deepgram.STT(
        model="nova-2-general",
        language="ru",
        interim_results=True,
        punctuate=True,
        smart_format=True,
    )
    tts = elevenlabs.TTS(
        voice_id=ELEVENLABS_VOICE_ID,
        model="eleven_turbo_v2_5",
        language="ru",
        api_key=os.getenv("ELEVENLABS_API_KEY") or os.getenv("ELEVEN_API_KEY"),
        voice_settings=elevenlabs.VoiceSettings(
            stability=0.35,
            similarity_boost=0.75,
            style=0.3,
            use_speaker_boost=True,
        ),
    )
    session = AgentSession(
        vad=vad,
        stt=stt,
        llm=openai.LLM(model="gpt-4o"),
        tts=tts,
    )

    room_name = ctx.room.name

    async def on_shutdown():
        try:
            duration_sec = int(time.time() - start_time)
            history = session.history.to_dict()
            messages = history.get("items", [])
            transcript_turns = []
            conversation_parts = []
            for msg in messages:
                if msg.get("type") != "message":
                    continue
                role = msg.get("role", "")
                content = msg.get("content")
                if isinstance(content, list):
                    text = " ".join(c for c in content if isinstance(c, str)).strip()
                else:
                    text = str(content or "").strip()
                if not text:
                    continue
                transcript_turns.append({"role": role, "text": text})
                speaker = "AI" if role == "assistant" else "Business"
                conversation_parts.append(f"{speaker}: {text}")

            conversation_text = "\n".join(conversation_parts)
            summary = await _summarize_call(conversation_text, metadata, transcript_turns)

            logger.info(
                "[shutdown] room=%s: %d turns, %ds, summary=%r",
                room_name, len(transcript_turns), duration_sec, summary[:80],
            )
            # Log full transcript
            for turn in transcript_turns:
                logger.info("[transcript] %s: %s", turn["role"], turn["text"])

            await _post_callback(metadata, transcript_turns, summary, duration_sec)
        except Exception as e:
            logger.exception("[shutdown] Failed to save transcript: %s", e)

    ctx.add_shutdown_callback(on_shutdown)

    import asyncio
    from livekit import rtc

    # Pre-generate the greeting audio in parallel with waiting for peer pickup.
    # ElevenLabs turbo v2.5 time-to-first-byte is ~300-500ms; doing it during
    # the ring improves perceived latency at pickup ~6s → <300ms.
    GREETING_TEXT = "Здравствуйте!"
    pregen_t0 = time.time()
    async def _pregen_greeting():
        frames = []
        try:
            stream = tts.synthesize(GREETING_TEXT)
            async for ev in stream:
                # livekit TTS yields SynthesizedAudio objects with .frame (rtc.AudioFrame)
                frame = getattr(ev, "frame", None)
                if frame is not None:
                    frames.append(frame)
            await stream.aclose()
            logger.info("[timing] pregen ready in %.0fms (%d frames)",
                        (time.time() - pregen_t0) * 1000, len(frames))
        except Exception as e:
            logger.warning("pregen greeting failed: %s", e)
        return frames
    pregen_task = asyncio.create_task(_pregen_greeting())

    # Pre-warm Silero VAD in background.
    async def _warmup_vad():
        try:
            import numpy as np
            silent = np.zeros(16000, dtype=np.int16).tobytes()
            frame = rtc.AudioFrame(silent, 16000, 1, 16000)
            stream = vad.stream()
            stream.push_frame(frame)
            stream.end_input()
            async for _ in stream:
                break
            await stream.aclose()
        except Exception as e:
            logger.debug("VAD warmup skipped: %s", e)
    asyncio.create_task(_warmup_vad())

    # Start session immediately — audio pipeline comes up while we wait for peer.
    await session.start(
        agent=Agent(instructions=instructions),
        room=ctx.room,
        room_input_options=RoomInputOptions(
            participant_kinds=[rtc.ParticipantKind.PARTICIPANT_KIND_SIP],
        ),
    )

    # Event-driven wait for the peer (SIP INVITE — not yet answered).
    try:
        sip_peer = await asyncio.wait_for(
            ctx.wait_for_participant(kind=rtc.ParticipantKind.PARTICIPANT_KIND_SIP),
            timeout=60,
        )
    except asyncio.TimeoutError:
        logger.warning("[call] No SIP peer after 60s, exiting")
        await ctx.room.disconnect()
        return
    invite_t = time.time()
    logger.info("[call] SIP participant registered (INVITE): %s", sip_peer.identity)

    # Wait for ACTUAL answer via sip.callStatus attribute transition to "active".
    # Values: "dialing" (INVITE sent) → "ringing" → "active" (200 OK received).
    # Before "active", livekit-sip discards any audio we publish (no media
    # destination yet), so we must hold off on session.say.
    answered = asyncio.Event()

    async def _poll_status():
        for _ in range(600):  # up to 60s
            attrs = sip_peer.attributes or {}
            status = attrs.get("sip.callStatus")
            if status == "active":
                answered.set()
                return
            if status in ("hangup", "error"):
                return
            await asyncio.sleep(0.1)

    poll_task = asyncio.create_task(_poll_status())
    try:
        await asyncio.wait_for(answered.wait(), timeout=60)
    except asyncio.TimeoutError:
        logger.warning("[call] No answer after 60s — hanging up")
        poll_task.cancel()
        await ctx.room.disconnect()
        return
    poll_task.cancel()

    peer_t = time.time()
    logger.info("[call] Answered %.0fms after INVITE (callStatus=%s)",
                (peer_t - invite_t) * 1000,
                (sip_peer.attributes or {}).get("sip.callStatus", "n/a"))

    # Fire greeting immediately — session.say returns SpeechHandle synchronously.
    # No await: we want audio publishing to start in the background NOW.
    pregen_frames = await pregen_task
    logger.info("[timing] pregen awaited (total %.0fms), %d frames",
                (time.time() - pregen_t0) * 1000, len(pregen_frames) if pregen_frames else 0)
    if pregen_frames:
        async def _iter_frames():
            for f in pregen_frames:
                yield f
        session.say(GREETING_TEXT, audio=_iter_frames(), allow_interruptions=True)
    else:
        session.say(GREETING_TEXT, allow_interruptions=True)
    logger.info("[timing] greeting scheduled %.0fms after peer_joined",
                (time.time() - peer_t) * 1000)

    # Wait for: agent says goodbye, peer disconnect, or timeout (15 min)
    goodbye_words = ['до свидания', 'всего доброго', 'до встречи', 'goodbye', 'всего хорошего']
    last_check_len = 0
    for _ in range(900):
        await asyncio.sleep(1)
        # Check if peer left
        peers = [p for p in ctx.room.remote_participants.values()
                 if p.identity != "meeting-recorder" and not p.identity.startswith("listener-")]
        if not peers:
            logger.info("[hangup] Peer left")
            break
        # Check agent history for goodbye
        try:
            history = session.history.to_dict()
            items = history.get("items", [])
            if len(items) > last_check_len:
                last_check_len = len(items)
                for item in items[-3:]:
                    if item.get("role") == "assistant":
                        content = item.get("content", "")
                        if isinstance(content, list):
                            text = " ".join(c for c in content if isinstance(c, str))
                        else:
                            text = str(content or "")
                        if any(w in text.lower() for w in goodbye_words):
                            logger.info("[goodbye] Agent said goodbye, disconnecting in 3s")
                            await asyncio.sleep(3)
                            # Check once more if peer already left
                            peers2 = [p for p in ctx.room.remote_participants.values()
                                      if p.identity != "meeting-recorder" and not p.identity.startswith("listener-")]
                            if not peers2:
                                logger.info("[goodbye] Peer already left")
                            break
                else:
                    continue
                break
        except Exception:
            pass
    else:
        logger.info("[timeout] Call timed out after 15 min")

    await asyncio.sleep(2)
    logger.info("[disconnect] Leaving room %s", room_name)

    # Delete the room — this drops the SIP participant too (hangs up the phone call)
    try:
        from livekit import api as lk_api
        lkapi = lk_api.LiveKitAPI()
        await lkapi.room.delete_room(lk_api.DeleteRoomRequest(room=room_name))
        logger.info("[hangup] room deleted — SIP call terminated")
        await lkapi.aclose()
    except Exception as e:
        logger.warning("[hangup] failed to delete room: %s", e)

    # Also disconnect self just in case
    try:
        await ctx.room.disconnect()
    except Exception:
        pass


if __name__ == "__main__":
    cli.run_app(
        WorkerOptions(
            entrypoint_fnc=entrypoint,
            agent_name="outbound-call-agent",
            port=18082,
            prometheus_port=19465,
            job_memory_warn_mb=400,
            job_memory_limit_mb=600,
        )
    )
