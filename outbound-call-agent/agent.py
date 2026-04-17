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


async def _summarize_call(conversation_text: str, metadata: dict) -> str:
    if not conversation_text.strip():
        return ""
    client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    business_name = metadata.get("businessName", "компания")
    task_context = metadata.get("taskContext", "")
    try:
        resp = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": (
                    "Ты суммаризуешь телефонный разговор с компанией. "
                    "Выдай краткую выжимку: что узнали, какие цены/сроки "
                    "назвали, есть ли наличие, контакты. Формат: "
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
            temperature=0.3,
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
        "X-Outbound-Secret": CALLBACK_SECRET,
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

    session = AgentSession(
        vad=silero.VAD.load(),
        stt=deepgram.STT(
            model="nova-2-general",
            language="ru",
            interim_results=True,
            punctuate=True,
            smart_format=True,
        ),
        llm=openai.LLM(model="gpt-4o"),
        tts=elevenlabs.TTS(
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
        ),
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
            summary = await _summarize_call(conversation_text, metadata)

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

    await session.start(
        agent=Agent(instructions=instructions),
        room=ctx.room,
    )

    # Start the conversation — the agent is the caller
    # IMPORTANT: Only greet. Do NOT ask questions yet — wait for the other side to respond.
    greeting = (
        "Скажи только 'Здравствуйте!' — и ничего больше. "
        "Жди ответ собеседника. Не задавай вопросов пока он не ответит на приветствие."
    )
    await session.generate_reply(instructions=greeting)

    # Wait for any other participant to join (SIP or another agent for testing)
    peer_joined = False
    for _ in range(30):
        await asyncio.sleep(1)
        peers = [p for p in ctx.room.remote_participants.values()
                 if p.identity != "meeting-recorder"]
        if peers:
            peer_joined = True
            logger.info("[call] Peer joined: %s", peers[0].identity)
            break

    if not peer_joined:
        logger.warning("[call] No peer after 30s, exiting")
        await ctx.room.disconnect()
        return

    # Wait for: agent says goodbye, peer disconnect, or timeout (15 min)
    goodbye_words = ['до свидания', 'всего доброго', 'до встречи', 'goodbye', 'всего хорошего']
    last_check_len = 0
    for _ in range(900):
        await asyncio.sleep(1)
        # Check if peer left
        peers = [p for p in ctx.room.remote_participants.values()
                 if p.identity != "meeting-recorder"]
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
                                      if p.identity != "meeting-recorder"]
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

    # Disconnect — backend will delete room after receiving callback
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
