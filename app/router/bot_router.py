from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from app.bot.nodes import graph
from pydantic import BaseModel
from typing import AsyncGenerator, Dict, Optional, ContextManager
import contextlib
from datetime import datetime, timedelta
import uuid



router = APIRouter(
    prefix='/bot',
    tags=['Rafike ChatBot']
)


# Store for active user sessions 
# In production, you would use a proper database or cache system 
active_sessions: Dict[str, Dict] = {}

config = {
    "configurable": {
        "thread_id": "sdfdq"
    }
}

class ChatInput(BaseModel):
    message: str
    # session_id: Optional[str] = None


async def generate_stream_response(user_input: str) -> AsyncGenerator[str, None]:
    """Generate streaming response from the graph"""
    for chunk,  metadata in graph.stream({"messages": {"role": "user", "content": user_input}}, config, stream_mode="messages"):
        if metadata['langgraph_node'] == "agent":
            if chunk.content:
                print(chunk.content, end='', flush=True)
                yield chunk.content


# @router.post('/chat')
# def chat(chat_input: ChatInput):
#     for chunk, metadata in graph.stream({"messages": {"role": "user", "content": chat_input}}, config, stream_mode="messages"):
#         if metadata['langgraph_node'] == "agent":
#             print(chunk.content, end='', flush=True)


@router.post('/chat')
async def chat(chat_input: ChatInput):
    """Chat endpoint for the bot"""
    try:
        return StreamingResponse(
            generate_stream_response(chat_input.message),
            media_type="text/event-stream",

        )
    except Exception as e:
        return {"error": str(e)}